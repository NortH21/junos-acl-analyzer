package main

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed templates/*.html
var templatesFS embed.FS

// html/template экранирует пользовательский ввод с учетом контекста (HTML, атрибуты, URL)
var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"join": func(items []string, sep string) string {
		return strings.Join(items, sep)
	},
	"hasPrefix": func(s, prefix string) bool {
		return strings.HasPrefix(s, prefix)
	},
	"jiraLink":   jiraLink,
	"netboxLink": netboxLink,
}).ParseFS(templatesFS, "templates/*.html"))

// Префикс-лист Juniper
type PrefixList struct {
	Name     string
	Prefixes []string
}

// Term политики Juniper
type PolicyTerm struct {
	Name                   string
	SourceAddresses        []string
	DestinationAddresses   []string
	SourcePrefixLists      []string
	DestinationPrefixLists []string
	Protocol               string
	SourcePorts            []string
	DestinationPorts       []string
	Action                 string
	Counter                string
}

// Полное правило
type PolicyRule struct {
	FilterName                  string
	Term                        PolicyTerm
	ResolvedSourcePrefixes      []string // Разрешенные префиксы из префикс-листов
	ResolvedDestinationPrefixes []string // Разрешенные префиксы для destination
}

// Хранит состояние приложения
type AppState struct {
	PrefixLists map[string][]string
	PolicyRules []PolicyRule
}

// Результат поиска
type SearchResult struct {
	Query        string
	MatchedRules []PolicyRule
}

// Для статистики приложения
type AppStats struct {
	PrefixListCount int
	RuleCount       int
	MemoryUsage     string
	Goroutines      int
	Uptime          string
}

// Представляет сгруппированное правило
type GroupedRule struct {
	TermName               string
	SourcePrefixes         []string
	DestinationPrefixes    []string
	SourcePrefixLists      []string
	DestinationPrefixLists []string
	Protocol               string
	SourcePorts            []string
	DestinationPorts       []string
	Action                 string
	Filters                []string // Список фильтров, где встречается это правило
}

// Данные для страницы проверки
type CheckPageData struct {
	Src           string
	Dst           string
	Port          string
	Filter        string
	AllFilters    []string // Список всех фильтров
	Checked       bool
	AccessGranted bool
	AccessPartial bool
	MatchingRules []GroupedRule
}

var startTime time.Time

// Текущее состояние. Обработчики читают его без блокировок, а перезагрузка
// собирает новое состояние отдельно и подменяет указатель целиком
var currentState atomic.Pointer[AppState]

// Не дает перезагрузкам выполняться одновременно
var reloadMu sync.Mutex

func init() {
	currentState.Store(newAppState())
}

func newAppState() *AppState {
	return &AppState{
		PrefixLists: make(map[string][]string),
		PolicyRules: []PolicyRule{},
	}
}

// Возвращает снимок состояния, который не меняется после публикации
func getState() *AppState {
	return currentState.Load()
}

func main() {
	startTime = time.Now()

	// Парсинг файлов
	if err := loadConfigFiles(); err != nil {
		log.Printf("⚠️ Initial load error: %v", err)
	}
	// Автообновление каждые 2 минут
	go autoReloadConfigs(2 * time.Minute)

	// Настройка HTTP-обработчиков
	handler := newHandler()

	log.Printf("✅ Server started on http://localhost:8080") // TODO: Вынести адрес и порт в конфиг
	log.Println("📊 Prefix lists loaded:", len(getState().PrefixLists))
	log.Println("📊 Policy rules loaded:", len(getState().PolicyRules))

	if err := http.ListenAndServe(":8080", handler); err != nil { // TODO: Вынести порт в конфиг
		log.Printf("❌ Server startup error: %v\n", err)
	}
}

// Собирает HTTP-обработчики приложения
func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/check", checkHandler)
	mux.HandleFunc("/api/memory", apiMemoryHandler)

	return securityHeaders(mux)
}

// Добавляет защитные заголовки ко всем ответам
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// В строке запроса внутренние адреса, не отдаем их сторонним хостам
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Рендерит шаблон в буфер, чтобы при ошибке не отдать половину страницы
func renderTemplate(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("❌ Template %s error: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(w); err != nil {
		log.Printf("⚠️ Response write error: %v", err)
	}
}

// Ссылка на задачу в Jira. Запрос экранируется здесь: html/template не знает,
// что базовый URL из окружения заканчивается путем или строкой запроса
func jiraLink(query string) string {
	base := os.Getenv("JIRA_URL")
	if base == "" {
		base = "https://jira.example.com/browse/"
	}
	return base + url.PathEscape(query)
}

// Ссылка на поиск в Netbox
func netboxLink(query string) string {
	base := os.Getenv("NETBOX_URL")
	if base == "" {
		base = "https://netbox.example.com/search/?q="
	}
	return base + url.QueryEscape(query)
}

// Ищет правила и группирует их
func searchRulesWithGrouping(state *AppState, query string) []GroupedRule {
	groupedRules := make(map[string]*GroupedRule)

	for _, rule := range state.PolicyRules {
		if !isSearchMatch(rule, query) {
			continue
		}

		// Создаем ключ для группировки
		key := fmt.Sprintf("%s|%v|%v|%s|%v|%v|%s",
			rule.Term.Name,
			sortedSlice(rule.Term.SourcePrefixLists),
			sortedSlice(rule.Term.DestinationPrefixLists),
			rule.Term.Protocol,
			sortedSlice(rule.Term.SourcePorts),
			sortedSlice(rule.Term.DestinationPorts),
			rule.Term.Action)

		if groupedRule, exists := groupedRules[key]; !exists {
			groupedRules[key] = &GroupedRule{
				TermName:               rule.Term.Name,
				SourcePrefixes:         uniqueStrings(rule.ResolvedSourcePrefixes),
				DestinationPrefixes:    uniqueStrings(rule.ResolvedDestinationPrefixes),
				SourcePrefixLists:      uniqueStrings(rule.Term.SourcePrefixLists),
				DestinationPrefixLists: uniqueStrings(rule.Term.DestinationPrefixLists),
				Protocol:               rule.Term.Protocol,
				SourcePorts:            uniqueStrings(rule.Term.SourcePorts),
				DestinationPorts:       uniqueStrings(rule.Term.DestinationPorts),
				Action:                 rule.Term.Action,
				Filters:                []string{rule.FilterName},
			}
		} else {
			// Добавляем фильтр, если его еще нет
			if !containsString(groupedRule.Filters, rule.FilterName) {
				groupedRule.Filters = append(groupedRule.Filters, rule.FilterName)
			}

			// Добавляем уникальные префиксы
			groupedRule.SourcePrefixes = appendUnique(groupedRule.SourcePrefixes, rule.ResolvedSourcePrefixes...)
			groupedRule.DestinationPrefixes = appendUnique(groupedRule.DestinationPrefixes, rule.ResolvedDestinationPrefixes...)
		}
	}

	// Конвертируем map в slice и сортируем
	result := make([]GroupedRule, 0, len(groupedRules))
	for _, rule := range groupedRules {
		sort.Strings(rule.Filters)
		result = append(result, *rule)
	}

	// Сортируем по имени term
	sort.Slice(result, func(i, j int) bool {
		return result[i].TermName < result[j].TermName
	})

	return result
}

// Проверяет совпадает ли правило с поисковым запросом
func isSearchMatch(rule PolicyRule, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))

	// Проверяем source адреса
	for _, source := range rule.ResolvedSourcePrefixes {
		if matchesCIDR(query, source) || strings.Contains(strings.ToLower(source), query) {
			return true
		}
	}

	// Проверяем destination адреса
	for _, dest := range rule.ResolvedDestinationPrefixes {
		if matchesCIDR(query, dest) || strings.Contains(strings.ToLower(dest), query) {
			return true
		}
	}

	// Проверяем по имени префикс-листа
	for _, listName := range rule.Term.SourcePrefixLists {
		if strings.Contains(strings.ToLower(listName), query) {
			return true
		}
	}

	for _, listName := range rule.Term.DestinationPrefixLists {
		if strings.Contains(strings.ToLower(listName), query) {
			return true
		}
	}

	// Проверяем по имени term
	if strings.Contains(strings.ToLower(rule.Term.Name), query) {
		return true
	}

	return false
}

// Загружает конфигурационные файлы и публикует новое состояние
func loadConfigFiles() error {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	log.Println("🔄 Loading configuration files...")

	oldState := getState()
	newState, loadErr := buildState()

	log.Printf("✅ Loaded: %d prefix lists, %d rules",
		len(newState.PrefixLists), len(newState.PolicyRules))

	// Если ни один файл не загрузился, оставляем старое состояние
	if len(newState.PrefixLists) == 0 && len(newState.PolicyRules) == 0 {
		log.Println("⚠️ No data loaded, keeping old state")
		return fmt.Errorf("no data loaded from any file")
	}

	// Файл мог читаться в момент обновления репозитория. Частичные данные хуже
	// устаревших, поэтому при ошибке оставляем уже загруженное состояние
	oldHasData := len(oldState.PrefixLists) > 0 || len(oldState.PolicyRules) > 0
	if loadErr != nil && oldHasData {
		log.Println("⚠️ Load finished with errors, keeping old state")
		return loadErr
	}

	currentState.Store(newState)
	return loadErr
}

// Собирает состояние из файлов, не трогая опубликованное
func buildState() (*AppState, error) {
	state := newAppState()

	// Шаблоны файлов которые парсим
	aclPatterns := []string{
		"./jcore-filters/jcore*.acl.txt",
	}

	confPatterns := []string{
		"./jcore-filters/jcore*.acl.conf.txt",
	}

	// Собираем все файлы
	var allAclFiles []string
	var allConfFiles []string

	for _, pattern := range aclPatterns {
		files, _ := filepath.Glob(pattern)
		allAclFiles = append(allAclFiles, files...)
	}

	for _, pattern := range confPatterns {
		files, _ := filepath.Glob(pattern)
		allConfFiles = append(allConfFiles, files...)
	}

	// Убираем дубликаты
	allAclFiles = uniqueFiles(allAclFiles)
	allConfFiles = uniqueFiles(allConfFiles)

	log.Printf("📁 Found ACL files: %v", allAclFiles)
	log.Printf("📁 Found CONF files: %v", allConfFiles)

	var errs []error

	// Парсим ACL файлы
	for _, aclFile := range allAclFiles {
		if err := parsePrefixLists(state, aclFile); err != nil {
			log.Printf("⚠️ ACL file error %s: %v", aclFile, err)
			errs = append(errs, fmt.Errorf("%s: %w", aclFile, err))
		}
	}

	// Парсим CONF файлы
	for _, confFile := range allConfFiles {
		if err := parsePolicyRules(state, confFile); err != nil {
			log.Printf("⚠️ CONF file error %s: %v", confFile, err)
			errs = append(errs, fmt.Errorf("%s: %w", confFile, err))
		}
	}

	// Разворачивает префикс-листы
	resolvePrefixLists(state)

	return state, errors.Join(errs...)
}

// Удаляет дубликаты из списка файлов
func uniqueFiles(files []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, file := range files {
		if !seen[file] {
			seen[file] = true
			result = append(result, file)
		}
	}

	// Сортируем для консистентности
	sort.Strings(result)
	return result
}

// Автоматически перезагружает конфиги по таймеру
func autoReloadConfigs(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := loadConfigFiles(); err != nil {
			log.Printf("⚠️ Error while reloading files: %v", err)
		}
	}
}

// Парсит файл с префикс-листами
func parsePrefixLists(state *AppState, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Ищем строки с префикс-листами
		if strings.Contains(line, "prefix-list") {
			// Пример: set policy-options prefix-list OPR-WEB-INTERNAL 10.237.241.0/24
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				listName := parts[3]
				prefix := parts[4]

				state.PrefixLists[listName] = append(state.PrefixLists[listName], prefix)
			}
		}
	}

	return scanner.Err()
}

// Парсит файл с политиками
func parsePolicyRules(state *AppState, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentFilter string
	var currentTerm *PolicyTerm
	var inFilter, inTerm bool
	var currentSection string
	var blockDepth int
	var inSourceAddressBlock, inDestinationAddressBlock bool
	var inSourcePrefixListBlock, inDestinationPrefixListBlock bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки
		if line == "" {
			continue
		}

		// Начало фильтра
		if strings.HasPrefix(line, "filter ") {
			filterName := strings.TrimPrefix(line, "filter ")
			filterName = strings.TrimSuffix(filterName, " {")
			currentFilter = filterName
			inFilter = true
			blockDepth = 1
			continue
		}

		if !inFilter {
			continue
		}

		// Отслеживаем глубину вложенности
		if strings.HasSuffix(line, "{") {
			blockDepth++
		}
		if strings.HasPrefix(line, "}") {
			blockDepth--
			if blockDepth == 0 {
				// Конец фильтра
				inFilter = false
				currentFilter = ""
			}

			// Закрытие блоков внутри term
			if inTerm {
				if inSourceAddressBlock {
					inSourceAddressBlock = false
					continue
				}
				if inDestinationAddressBlock {
					inDestinationAddressBlock = false
					continue
				}
				if inSourcePrefixListBlock {
					inSourcePrefixListBlock = false
					continue
				}
				if inDestinationPrefixListBlock {
					inDestinationPrefixListBlock = false
					continue
				}
				if currentSection != "" {
					currentSection = ""
				} else if blockDepth > 0 {
					// Конец term
					if currentTerm != nil {
						state.PolicyRules = append(state.PolicyRules, PolicyRule{
							FilterName: currentFilter,
							Term:       *currentTerm,
						})
						currentTerm = nil
					}
					inTerm = false
				}
			}
			continue
		}

		// Начало term
		if strings.HasPrefix(line, "term ") && inFilter {
			if currentTerm != nil {
				state.PolicyRules = append(state.PolicyRules, PolicyRule{
					FilterName: currentFilter,
					Term:       *currentTerm,
				})
			}
			termName := strings.TrimPrefix(line, "term ")
			termName = strings.TrimSuffix(termName, " {")
			currentTerm = &PolicyTerm{
				Name:   termName,
				Action: "accept", // по умолчанию
			}
			inTerm = true
			continue
		}

		if !inTerm {
			continue
		}

		// Разделы (from, then)
		if line == "from {" {
			currentSection = "from"
			continue
		} else if line == "then {" {
			currentSection = "then"
			continue
		} else if currentSection == "" && strings.HasPrefix(line, "then ") && strings.HasSuffix(line, ";") {
			// Однострочная форма: "then discard;"
			if currentTerm != nil {
				parseThenSection(strings.TrimPrefix(line, "then "), currentTerm)
			}
			continue
		}

		// Парсинг содержимого разделов
		if currentSection == "from" && currentTerm != nil {
			parseFromSection(line, currentTerm, &inSourceAddressBlock, &inDestinationAddressBlock,
				&inSourcePrefixListBlock, &inDestinationPrefixListBlock)
		} else if currentSection == "then" && currentTerm != nil {
			parseThenSection(line, currentTerm)
		}
	}

	// Добавляем последний term, если есть
	if currentTerm != nil && inFilter {
		state.PolicyRules = append(state.PolicyRules, PolicyRule{
			FilterName: currentFilter,
			Term:       *currentTerm,
		})
	}

	return scanner.Err()
}

// Парсит секцию "from"
func parseFromSection(line string, term *PolicyTerm,
	inSourceAddressBlock, inDestinationAddressBlock *bool,
	inSourcePrefixListBlock, inDestinationPrefixListBlock *bool) {

	// Обработка source-address
	if strings.HasPrefix(line, "source-address {") {
		*inSourceAddressBlock = true
		return
	}
	if *inSourceAddressBlock && strings.HasSuffix(line, ";") {
		addr := strings.TrimSuffix(line, ";")
		term.SourceAddresses = append(term.SourceAddresses, strings.TrimSpace(addr))
		return
	}

	// Обработка destination-address
	if strings.HasPrefix(line, "destination-address {") {
		*inDestinationAddressBlock = true
		return
	}
	if *inDestinationAddressBlock && strings.HasSuffix(line, ";") {
		addr := strings.TrimSuffix(line, ";")
		term.DestinationAddresses = append(term.DestinationAddresses, strings.TrimSpace(addr))
		return
	}

	// Обработка source-prefix-list
	if strings.HasPrefix(line, "source-prefix-list {") {
		*inSourcePrefixListBlock = true
		return
	}
	if *inSourcePrefixListBlock && strings.HasSuffix(line, ";") {
		listName := strings.TrimSuffix(line, ";")
		term.SourcePrefixLists = append(term.SourcePrefixLists, strings.TrimSpace(listName))
		return
	}

	// Обработка destination-prefix-list
	if strings.HasPrefix(line, "destination-prefix-list {") {
		*inDestinationPrefixListBlock = true
		return
	}
	if *inDestinationPrefixListBlock && strings.HasSuffix(line, ";") {
		listName := strings.TrimSuffix(line, ";")
		term.DestinationPrefixLists = append(term.DestinationPrefixLists, strings.TrimSpace(listName))
		return
	}

	// Обработка protocol
	if strings.HasPrefix(line, "protocol ") {
		term.Protocol = strings.TrimSuffix(strings.TrimPrefix(line, "protocol "), ";")
		return
	}

	// Обработка source-port
	if strings.HasPrefix(line, "source-port ") {
		ports := strings.TrimSuffix(strings.TrimPrefix(line, "source-port "), ";")
		term.SourcePorts = append(term.SourcePorts, ports)
		return
	}

	// Обработка destination-port
	if strings.HasPrefix(line, "destination-port ") {
		ports := strings.TrimSuffix(strings.TrimPrefix(line, "destination-port "), ";")
		// Парсим порты из строки с диапазонами
		parsedPorts := parsePortRange(ports)
		term.DestinationPorts = append(term.DestinationPorts, parsedPorts...)
		return
	}
}

// Парсит секцию "then"
func parseThenSection(line string, term *PolicyTerm) {
	stmt := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
	fields := strings.Fields(stmt)
	if len(fields) == 0 {
		return
	}

	switch fields[0] {
	case "count":
		if len(fields) > 1 {
			term.Counter = fields[1]
		}
	case "accept":
		term.Action = "accept"
	case "reject", "deny":
		// reject может иметь аргумент (например, tcp-reset)
		term.Action = "reject"
	case "discard":
		// discard может иметь аргумент (например, accounting)
		term.Action = "discard"
	case "next":
		// "next term" - нетерминирующее действие, обработка идет дальше
		if len(fields) > 1 && fields[1] == "term" {
			term.Action = "next"
		}
	}
}

// Разворачивает префикс-листы в конкретные префиксы
func resolvePrefixLists(state *AppState) {
	missing := make(map[string]bool)

	for i, rule := range state.PolicyRules {
		var resolvedSourcePrefixes []string
		var resolvedDestinationPrefixes []string

		// Добавляем прямые source-address
		resolvedSourcePrefixes = append(resolvedSourcePrefixes, rule.Term.SourceAddresses...)

		// Разворачивает source префикс-листы
		for _, listName := range rule.Term.SourcePrefixLists {
			if prefixes, exists := state.PrefixLists[listName]; exists {
				resolvedSourcePrefixes = append(resolvedSourcePrefixes, prefixes...)
			} else {
				missing[listName] = true
			}
		}

		// Добавляем прямые destination-address
		resolvedDestinationPrefixes = append(resolvedDestinationPrefixes, rule.Term.DestinationAddresses...)

		// Разворачивает destination префикс-листы
		for _, listName := range rule.Term.DestinationPrefixLists {
			if prefixes, exists := state.PrefixLists[listName]; exists {
				resolvedDestinationPrefixes = append(resolvedDestinationPrefixes, prefixes...)
			} else {
				missing[listName] = true
			}
		}

		state.PolicyRules[i].ResolvedSourcePrefixes = resolvedSourcePrefixes
		state.PolicyRules[i].ResolvedDestinationPrefixes = resolvedDestinationPrefixes
	}

	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for name := range missing {
			names = append(names, name)
		}
		sort.Strings(names)
		log.Printf("⚠️ Prefix lists referenced but not defined (%d): %v", len(names), names)
	}
}

// Проверяет, попадает ли IP/префикс под CIDR
func matchesCIDR(query, cidr string) bool {
	if query == cidr {
		return true
	}

	// Если ищем IP без маски
	if !strings.Contains(query, "/") && strings.Contains(cidr, "/") {
		// Парсим CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}

		// Парсим запрос как IP
		queryIP := net.ParseIP(query)
		if queryIP == nil {
			return false
		}

		// Проверяем вхождение IP в сеть
		return ipNet.Contains(queryIP)
	}

	// Если оба с маской, сравниваем как строки
	return query == cidr
}

// Обработчики HTTP
func homeHandler(w http.ResponseWriter, r *http.Request) {
	state := getState()

	data := struct {
		Stats       AppStats
		SampleRules []PolicyRule
	}{
		Stats: AppStats{
			PrefixListCount: len(state.PrefixLists),
			RuleCount:       len(state.PolicyRules),
			MemoryUsage:     getMemoryUsage(),
			Goroutines:      runtime.NumGoroutine(),
			Uptime:          getUptime(),
		},
	}

	// Берем последние 3 правила для примера
	if len(state.PolicyRules) > 3 {
		data.SampleRules = state.PolicyRules[len(state.PolicyRules)-3:]
	} else {
		data.SampleRules = state.PolicyRules
	}

	renderTemplate(w, "index.html", data)
}

// Обработчик поиска
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	results := searchRulesWithGrouping(getState(), query)

	data := struct {
		Query        string
		MatchedRules []GroupedRule
		MemoryUsage  string
		SearchTime   string
	}{
		Query:        query,
		MatchedRules: results,
		MemoryUsage:  getMemoryUsage(),
		SearchTime:   time.Now().Format("15:04:05"),
	}

	renderTemplate(w, "results.html", data)
}

// Возвращает информацию об использовании памяти
func getMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Используем MB для отображения
	return fmt.Sprintf("%.2f MB", float64(m.Alloc)/1024/1024)
}

// Возвращает время работы приложения
func getUptime() string {
	duration := time.Since(startTime)

	if duration.Hours() > 24 {
		return fmt.Sprintf("%.0f days", duration.Hours()/24)
	} else if duration.Hours() > 1 {
		return fmt.Sprintf("%.0f hours", duration.Hours())
	} else if duration.Minutes() > 1 {
		return fmt.Sprintf("%.0f minutes", duration.Minutes())
	}
	return fmt.Sprintf("%.0f seconds", duration.Seconds())
}

// Обработчик API для информации о памяти и статистике
func apiMemoryHandler(w http.ResponseWriter, r *http.Request) {
	state := getState()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
        "memory": {
            "alloc": "%.2f MB",
            "total_alloc": "%.2f MB",
            "sys": "%.2f MB"
        },
        "goroutines": %d,
        "uptime": "%s",
        "data": {
            "prefix_lists": %d,
            "rules": %d
        }
    }`,
		float64(m.Alloc)/1024/1024,
		float64(m.TotalAlloc)/1024/1024,
		float64(m.Sys)/1024/1024,
		runtime.NumGoroutine(),
		time.Since(startTime).String(),
		len(state.PrefixLists),
		len(state.PolicyRules))
}

// checkHandler обрабатывает проверку доступа
func checkHandler(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	dst := r.URL.Query().Get("dst")
	port := r.URL.Query().Get("port")
	filter := r.URL.Query().Get("filter")
	state := getState()

	data := CheckPageData{
		Src:        src,
		Dst:        dst,
		Port:       port,
		AllFilters: getAllFilterNames(state),
	}

	// Если все поля пустые, просто показываем форму
	if src == "" && dst == "" && port == "" {
		renderTemplate(w, "check.html", data)
		return
	}

	// Ищем правила
	rules := checkAccess(state, src, dst, port)

	// Фильтруем по выбранному фильтру, если указан
	if filter != "" {
		filteredRules := []GroupedRule{}
		for _, rule := range rules {
			for _, f := range rule.Filters {
				if f == filter {
					filteredRules = append(filteredRules, rule)
					break
				}
			}
		}
		rules = filteredRules
	}

	data.Checked = true
	data.MatchingRules = rules

	// Определяем статус доступа
	if len(rules) > 0 {
		data.AccessGranted = true
	}

	renderTemplate(w, "check.html", data)
}

// Проверяет доступ по всем параметрам и возвращает сгруппированные правила
func checkAccess(state *AppState, src, dst, port string) []GroupedRule {
	groupedRules := make(map[string]*GroupedRule)

	for _, rule := range state.PolicyRules {
		// Проверяем совпадение правила с запросом
		if !isRuleMatch(rule, src, dst, port) {
			continue
		}

		// Создаем ключ для группировки (на основе основных параметров term)
		key := fmt.Sprintf("%s|%v|%v|%s|%v|%v|%s",
			rule.Term.Name,
			sortedSlice(rule.Term.SourcePrefixLists),
			sortedSlice(rule.Term.DestinationPrefixLists),
			rule.Term.Protocol,
			sortedSlice(rule.Term.SourcePorts),
			sortedSlice(rule.Term.DestinationPorts),
			rule.Term.Action)

		if groupedRule, exists := groupedRules[key]; !exists {
			// Создаем новое сгруппированное правило
			groupedRules[key] = &GroupedRule{
				TermName:               rule.Term.Name,
				SourcePrefixes:         uniqueStrings(rule.ResolvedSourcePrefixes),
				DestinationPrefixes:    uniqueStrings(rule.ResolvedDestinationPrefixes),
				SourcePrefixLists:      uniqueStrings(rule.Term.SourcePrefixLists),
				DestinationPrefixLists: uniqueStrings(rule.Term.DestinationPrefixLists),
				Protocol:               rule.Term.Protocol,
				SourcePorts:            uniqueStrings(rule.Term.SourcePorts),
				DestinationPorts:       uniqueStrings(rule.Term.DestinationPorts),
				Action:                 rule.Term.Action,
				Filters:                []string{rule.FilterName},
			}
		} else {
			// Добавляем фильтр, если его еще нет
			if !containsString(groupedRule.Filters, rule.FilterName) {
				groupedRule.Filters = append(groupedRule.Filters, rule.FilterName)
			}

			// Добавляем уникальные префиксы
			groupedRule.SourcePrefixes = appendUnique(groupedRule.SourcePrefixes, rule.ResolvedSourcePrefixes...)
			groupedRule.DestinationPrefixes = appendUnique(groupedRule.DestinationPrefixes, rule.ResolvedDestinationPrefixes...)
		}
	}

	// Конвертируем map в slice и сортируем по имени term
	result := make([]GroupedRule, 0, len(groupedRules))
	for _, rule := range groupedRules {
		// Сортируем фильтры для красивого отображения
		sort.Strings(rule.Filters)
		result = append(result, *rule)
	}

	// Сортируем результат по имени term
	sort.Slice(result, func(i, j int) bool {
		return result[i].TermName < result[j].TermName
	})

	return result
}

// Проверяет совпадает ли правило с запросом
func isRuleMatch(rule PolicyRule, src, dst, port string) bool {
	// Проверяем action
	if rule.Term.Action != "accept" {
		return false
	}

	// Проверяем source
	srcMatch := false
	if src == "" {
		// Если source не указан, считаем что совпадает с любым source
		srcMatch = true
	} else {
		// Если в терме нет условий по source, значит правило не ограничивает source.
		// Пустой или ненайденный префикс-лист - это условие, под которое ничего не попадает
		if len(rule.Term.SourceAddresses) == 0 && len(rule.Term.SourcePrefixLists) == 0 {
			srcMatch = true
		} else {
			// Проверяем совпадение по source
			for _, sourcePrefix := range rule.ResolvedSourcePrefixes {
				if matchesCIDR(src, sourcePrefix) {
					srcMatch = true
					break
				}
			}
		}
	}

	if !srcMatch {
		return false
	}

	// Проверяем destination
	dstMatch := false
	if dst == "" {
		// Если destination не указан, считаем что совпадает с любым destination
		dstMatch = true
	} else {
		// Если в терме нет условий по destination, значит правило не ограничивает destination
		if len(rule.Term.DestinationAddresses) == 0 && len(rule.Term.DestinationPrefixLists) == 0 {
			dstMatch = true
		} else {
			// Проверяем совпадение по destination
			for _, destPrefix := range rule.ResolvedDestinationPrefixes {
				if matchesCIDR(dst, destPrefix) {
					dstMatch = true
					break
				}
			}
		}
	}

	if !dstMatch {
		return false
	}

	portMatch := false
	if port == "" {
		// Если порт не указан, считаем что совпадает
		portMatch = true
	} else {
		// Проверяем порты в правиле
		if len(rule.Term.DestinationPorts) == 0 {
			// Если в правиле не указаны порты, значит все порты разрешены
			portMatch = true
		} else {
			// Проверяем каждый порт в правиле
			for _, rulePort := range rule.Term.DestinationPorts {
				if portMatches(port, rulePort) {
					portMatch = true
					break
				}
			}
		}
	}

	return portMatch
}

// Вспомогательные функции
func sortedSlice(items []string) []string {
	sorted := make([]string, len(items))
	copy(sorted, items)
	sort.Strings(sorted)
	return sorted
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func appendUnique(existing []string, newItems ...string) []string {
	result := existing
	seen := make(map[string]bool)

	for _, item := range existing {
		seen[item] = true
	}

	for _, item := range newItems {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Проверяет совпадение портов
func portMatches(queryPort, rulePort string) bool {
	queryPort = strings.TrimSpace(queryPort)
	rulePort = strings.TrimSpace(rulePort)

	// Простое совпадение
	if queryPort == rulePort {
		return true
	}

	// Приводим к нижнему регистру для сравнения
	queryLower := strings.ToLower(queryPort)
	ruleLower := strings.ToLower(rulePort)

	// Проверяем именованные порты (http, https, ssh и т.д.)
	if queryLower == ruleLower {
		return true
	}

	// Пробуем преобразовать queryPort в число
	queryNum, queryErr := strconv.Atoi(queryPort)

	// Проверяем диапазоны портов в rulePort
	if strings.Contains(rulePort, "-") {
		parts := strings.Split(rulePort, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				// Если queryPort - число
				if queryErr == nil && queryNum >= start && queryNum <= end {
					return true
				}
				// Если queryPort тоже диапазон
				if strings.Contains(queryPort, "-") {
					qParts := strings.Split(queryPort, "-")
					if len(qParts) == 2 {
						qStart, qErr1 := strconv.Atoi(strings.TrimSpace(qParts[0]))
						qEnd, qErr2 := strconv.Atoi(strings.TrimSpace(qParts[1]))
						if qErr1 == nil && qErr2 == nil {
							// Проверяем пересечение диапазонов
							if qStart <= end && qEnd >= start {
								return true
							}
						}
					}
				}
			}
		}
	}

	// Проверяем если queryPort - диапазон, а rulePort - одиночный порт
	if queryErr == nil && !strings.Contains(queryPort, "-") {
		// queryPort - число, rulePort - одиночный порт
		ruleNum, ruleErr := strconv.Atoi(rulePort)
		if ruleErr == nil && queryNum == ruleNum {
			return true
		}
	}

	// Специальные случаи
	if rulePort == "any" || rulePort == "all" || rulePort == "*" {
		return true
	}

	// Проверяем множественные порты (через запятую или пробел)
	if strings.Contains(rulePort, ",") || strings.Contains(rulePort, " ") {
		var ports []string
		if strings.Contains(rulePort, ",") {
			ports = strings.Split(rulePort, ",")
		} else {
			ports = strings.Fields(rulePort)
		}
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if portMatches(queryPort, p) {
				return true
			}
		}
	}

	return false
}

// Парсит порты из строки с диапазонами
func parsePortRange(portStr string) []string {
	portStr = strings.TrimSpace(portStr)
	var result []string

	// Если порт в квадратных скобках, убираем их
	if strings.HasPrefix(portStr, "[") && strings.HasSuffix(portStr, "]") {
		portStr = portStr[1 : len(portStr)-1]
	}

	// Разделяем по пробелам
	parts := strings.Fields(portStr)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

func getAllFilterNames(state *AppState) []string {
	filterMap := make(map[string]bool)

	for _, rule := range state.PolicyRules {
		filterMap[rule.FilterName] = true
	}

	filters := make([]string, 0, len(filterMap))
	for filter := range filterMap {
		filters = append(filters, filter)
	}

	sort.Strings(filters)
	return filters
}
