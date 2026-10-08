package main

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	// Условия "from", которые анализатор не проверяет. Терм с такими условиями
	// совпадает с запросом только частично
	OtherConditions []string
}

// Полное правило
type PolicyRule struct {
	FilterName                  string
	Term                        PolicyTerm
	ResolvedSourcePrefixes      []string // Разрешенные префиксы из префикс-листов
	ResolvedDestinationPrefixes []string // Разрешенные префиксы для destination

	// Разобранные адресные условия для сопоставления
	srcAddrs addrSet
	dstAddrs addrSet
	dstPorts portSet
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

// Максимальная длина строки конфига (длинные списки портов и адресов)
const maxLineSize = 1024 * 1024

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

	// Адрес или сеть ищем по пересечению: 10.1.1.5 находит 10.1.1.0/24,
	// а 10.1.0.0/16 находит все префиксы внутри
	if prefix, ok := parsePrefix(query); ok {
		return rule.srcAddrs.overlaps(prefix) || rule.dstAddrs.overlaps(prefix)
	}

	// Неполный адрес ("10.237.") ищем только с начала префикса,
	// иначе "10.1" находит и 110.1.0.0/16
	for _, source := range rule.ResolvedSourcePrefixes {
		if strings.HasPrefix(strings.ToLower(source), query) {
			return true
		}
	}

	for _, dest := range rule.ResolvedDestinationPrefixes {
		if strings.HasPrefix(strings.ToLower(dest), query) {
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
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Пример: set policy-options prefix-list OPR-WEB-INTERNAL 10.237.241.0/24
		// Строки с source-prefix-list и подобными сюда попадать не должны
		parts := strings.Fields(line)
		for i := 1; i+2 < len(parts); i++ {
			if parts[i-1] == "policy-options" && parts[i] == "prefix-list" {
				listName := parts[i+1]
				prefix := parts[i+2]

				state.PrefixLists[listName] = append(state.PrefixLists[listName], prefix)
				break
			}
		}
	}

	return scanner.Err()
}

// Парсит файл с политиками.
// Вложенность отслеживается стеком блоков: filter -> term -> from/then -> блок условий
func parsePolicyRules(state *AppState, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
	var stack []string
	var currentFilter string
	var currentTerm *PolicyTerm

	// Сохраняет разобранный term
	flushTerm := func() {
		if currentTerm != nil {
			state.PolicyRules = append(state.PolicyRules, PolicyRule{
				FilterName: currentFilter,
				Term:       *currentTerm,
			})
			currentTerm = nil
		}
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/*") {
			continue
		}

		opensBlock := strings.HasSuffix(line, "{")
		head := strings.TrimSpace(strings.TrimSuffix(line, "{"))

		// Вне фильтра ищем только его начало
		if len(stack) == 0 {
			name := strings.TrimSpace(strings.TrimPrefix(head, "filter "))
			if opensBlock && strings.HasPrefix(head, "filter ") && name != "" {
				currentFilter = name
				stack = append(stack, "filter")
			}
			continue
		}

		if strings.HasPrefix(line, "}") {
			closed := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if closed == "term" || len(stack) == 0 {
				flushTerm()
			}
			if len(stack) == 0 {
				currentFilter = ""
			}
			continue
		}

		inTerm := len(stack) >= 2 && stack[1] == "term" && currentTerm != nil

		switch {
		case len(stack) == 1 && opensBlock && strings.HasPrefix(head, "term "):
			currentTerm = &PolicyTerm{
				Name:   strings.TrimSpace(strings.TrimPrefix(head, "term ")),
				Action: "accept", // по умолчанию
			}
			stack = append(stack, "term")

		case opensBlock:
			// from, then, блоки условий, а также всё незнакомое (например, "inactive: term X")
			stack = append(stack, head)

		case !inTerm:
			// Строки вне term нас не интересуют

		case len(stack) == 2:
			// Однострочные формы: "then discard;" и "from protocol tcp;"
			if strings.HasPrefix(line, "then ") {
				parseThenSection(strings.TrimPrefix(line, "then "), currentTerm)
			} else if strings.HasPrefix(line, "from ") {
				parseFromCondition(strings.TrimPrefix(line, "from "), currentTerm)
			}

		case len(stack) == 3 && stack[2] == "from":
			parseFromCondition(line, currentTerm)

		case len(stack) == 3 && stack[2] == "then":
			parseThenSection(line, currentTerm)

		case len(stack) == 4 && stack[2] == "from":
			parseFromBlockItem(stack[3], line, currentTerm)
		}
	}

	// Добавляем последний term, если файл оборван
	flushTerm()

	return scanner.Err()
}

// Парсит однострочное условие секции "from"
func parseFromCondition(line string, term *PolicyTerm) {
	condition := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
	if condition == "" {
		return
	}

	name, value, _ := strings.Cut(condition, " ")
	value = strings.TrimSpace(value)

	switch name {
	case "protocol":
		term.Protocol = value
	case "source-port":
		term.SourcePorts = append(term.SourcePorts, parsePortRange(value)...)
	case "destination-port":
		term.DestinationPorts = append(term.DestinationPorts, parsePortRange(value)...)
	case "source-address", "destination-address", "source-prefix-list", "destination-prefix-list":
		parseFromBlockItem(name, value, term)
	default:
		// Условие, которое мы не умеем проверять (tcp-established, icmp-type, port ...)
		term.OtherConditions = append(term.OtherConditions, condition)
	}
}

// Парсит элемент блока внутри "from", например адрес из source-address { ... }
func parseFromBlockItem(block, line string, term *PolicyTerm) {
	item := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
	if item == "" {
		return
	}

	switch block {
	case "source-address":
		term.SourceAddresses = append(term.SourceAddresses, item)
	case "destination-address":
		term.DestinationAddresses = append(term.DestinationAddresses, item)
	case "source-prefix-list":
		term.SourcePrefixLists = append(term.SourcePrefixLists, item)
	case "destination-prefix-list":
		term.DestinationPrefixLists = append(term.DestinationPrefixLists, item)
	default:
		// address { ... }, prefix-list { ... } и прочие блоки
		term.OtherConditions = append(term.OtherConditions, block+" "+item)
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
	invalid := make(map[string]bool)
	invalidPorts := make(map[string]bool)

	for i, rule := range state.PolicyRules {
		resolved, addrs := resolveAddresses(state, rule.Term.SourceAddresses, rule.Term.SourcePrefixLists, missing, invalid)
		state.PolicyRules[i].ResolvedSourcePrefixes = resolved
		state.PolicyRules[i].srcAddrs = addrs

		resolved, addrs = resolveAddresses(state, rule.Term.DestinationAddresses, rule.Term.DestinationPrefixLists, missing, invalid)
		state.PolicyRules[i].ResolvedDestinationPrefixes = resolved
		state.PolicyRules[i].dstAddrs = addrs

		state.PolicyRules[i].dstPorts = newPortSet(rule.Term.DestinationPorts)
		if state.PolicyRules[i].dstPorts.unknown {
			for _, spec := range rule.Term.DestinationPorts {
				if _, ok := parsePortSpec(spec); !ok {
					invalidPorts[spec] = true
				}
			}
		}
	}

	if len(missing) > 0 {
		log.Printf("⚠️ Prefix lists referenced but not defined (%d): %v", len(missing), sortedKeys(missing))
	}
	if len(invalid) > 0 {
		log.Printf("⚠️ Prefixes that could not be parsed (%d): %v", len(invalid), sortedKeys(invalid))
	}
	if len(invalidPorts) > 0 {
		log.Printf("⚠️ Ports that could not be parsed (%d): %v", len(invalidPorts), sortedKeys(invalidPorts))
	}
}

// Собирает адресное условие терма из прямых адресов и префикс-листов.
// Возвращает префиксы для отображения и разобранное условие для сопоставления
func resolveAddresses(state *AppState, addresses, listNames []string, missing, invalid map[string]bool) ([]string, addrSet) {
	var resolved []string
	addrs := addrSet{constrained: len(addresses) > 0 || len(listNames) > 0}

	add := func(text string, isExcept bool) {
		prefix, ok := parsePrefix(text)
		if !ok {
			invalid[text] = true
			return
		}
		if isExcept {
			addrs.except = append(addrs.except, prefix)
		} else {
			addrs.nets = append(addrs.nets, prefix)
		}
	}

	// Прямые адреса, в том числе "10.0.0.0/8 except"
	for _, address := range addresses {
		resolved = append(resolved, address)
		text, isExcept := strings.CutSuffix(address, " except")
		add(text, isExcept)
	}

	// Префикс-листы, в том числе "LIST except"
	for _, listName := range listNames {
		name, isExcept := strings.CutSuffix(listName, " except")
		prefixes, exists := state.PrefixLists[name]
		if !exists {
			missing[name] = true
			continue
		}
		for _, prefix := range prefixes {
			if isExcept {
				resolved = append(resolved, prefix+" except")
			} else {
				resolved = append(resolved, prefix)
			}
			add(prefix, isExcept)
		}
	}

	return resolved, addrs
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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

	// Проверяем source. Нераспознанный адрес не подходит ни под одно правило
	srcPrefix, srcOK := parsePrefix(src)
	if src != "" && !srcOK {
		return false
	}
	if rule.srcAddrs.match(srcPrefix, src != "") == matchNone {
		return false
	}

	// Проверяем destination
	dstPrefix, dstOK := parsePrefix(dst)
	if dst != "" && !dstOK {
		return false
	}
	if rule.dstAddrs.match(dstPrefix, dst != "") == matchNone {
		return false
	}

	// Проверяем порт. Нераспознанный порт не подходит ни под одно правило
	portQuery, portOK := parsePortSpec(port)
	if port != "" && !portOK {
		return false
	}
	return rule.dstPorts.match(portQuery, port != "") != matchNone
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
