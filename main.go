package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Скрипты и стили отдаем сами, без сторонних CDN
//
//go:embed static
var staticFS embed.FS

// html/template экранирует пользовательский ввод с учетом контекста (HTML, атрибуты, URL)
var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"join": func(items []string, sep string) string {
		return strings.Join(items, sep)
	},
	"isJiraQuery": isJiraQuery,
	"jiraLink":    jiraLink,
	"netboxLink":  netboxLink,
}).ParseFS(templatesFS, "templates/*.html"))

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
	Source                      string // Файл, из которого прочитан фильтр
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

	loadedAt    time.Time    // Когда загружены эти данные, то есть когда они последний раз менялись
	files       int          // Сколько файлов прочитано
	fingerprint string       // Хеш содержимого файлов, чтобы отличать реальные изменения
	problems    loadProblems // Что не удалось разобрать
}

// Значения из конфигов, которые не удалось разобрать или найти
type loadProblems struct {
	missingLists    []string // Префикс-листы, на которые есть ссылка, но нет определения
	invalidPrefixes []string
	invalidPorts    []string
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
	OtherConditions        []string // Условия, которые анализатор не проверяет
	Action                 string
	Filters                []string // Список фильтров, где встречается это правило
	ShadowedBy             []string // Запрещающие термы выше по фильтру, которые могут перехватить трафик
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
	BlockingRules []GroupedRule // Термы, которые запрещают запрошенный доступ
	Error         string        // Ошибка в параметрах запроса
	DataChanged   string        // Когда данные последний раз менялись
}

var startTime = time.Now()

// Максимальная длина строки конфига (длинные списки портов и адресов)
const maxLineSize = 1024 * 1024

// Текущее состояние. Обработчики читают его без блокировок, а перезагрузка
// собирает новое состояние отдельно и подменяет указатель целиком
var currentState atomic.Pointer[AppState]

// Не дает перезагрузкам выполняться одновременно
var reloadMu sync.Mutex

// Каталог с файлами фильтров (переменная FILTERS_DIR). Может быть символической
// ссылкой, которую git-sync переключает на новую версию репозитория
var filtersDir = defaultFiltersDir

const (
	defaultFiltersDir     = "./jcore-filters"
	defaultReloadInterval = 2 * time.Minute
	minReloadInterval     = time.Second
)

// Разбирает RELOAD_INTERVAL: как часто проверять файлы фильтров
func parseReloadInterval(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultReloadInterval, nil
	}

	interval, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q, expected a value like 30s or 2m", value)
	}
	if interval < minReloadInterval {
		return 0, fmt.Errorf("interval %s is too short, the minimum is %s", interval, minReloadInterval)
	}
	return interval, nil
}

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
	log := componentLogger("server")

	level, err := parseLogLevel(os.Getenv("LOG_LEVEL"))
	logLevel.Set(level)
	if err != nil {
		log.Warn("invalid LOG_LEVEL, using info", "error", err.Error())
	}

	trustedProxies, err = parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		log.Error("invalid TRUSTED_PROXIES", "error", err.Error())
		os.Exit(1)
	}

	reloadInterval, err := parseReloadInterval(os.Getenv("RELOAD_INTERVAL"))
	if err != nil {
		log.Error("invalid RELOAD_INTERVAL", "error", err.Error())
		os.Exit(1)
	}

	if dir := os.Getenv("FILTERS_DIR"); dir != "" {
		filtersDir = dir
	}

	// Адрес можно переопределить, например LISTEN_ADDR=127.0.0.1:9090
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Info("server starting",
		"listen_addr", addr,
		"filters_dir", filtersDir,
		"reload_interval_ms", reloadInterval.Milliseconds(),
		"log_level", levelName(level),
		"trusted_proxies", len(trustedProxies))

	// Kubernetes останавливает под сигналом SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// Ненулевой код, чтобы сбой запуска был виден оркестратору
		log.Error("cannot listen", "error", err.Error())
		os.Exit(1)
	}

	// Парсинг файлов. Результат и ошибки загрузчик пишет в лог сам
	_ = loadConfigFiles()
	go autoReloadConfigs(ctx, reloadInterval)

	if err := serve(ctx, listener, newHandler(), shutdownTimeout); err != nil {
		log.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}

// Собирает HTTP-обработчики приложения
func newHandler() http.Handler {
	mux := http.NewServeMux()
	// "{$}" ограничивает главную страницу корнем, остальные пути получают 404.
	// Приложение только читает данные, поэтому разрешен только GET
	mux.HandleFunc("GET /{$}", homeHandler)
	mux.HandleFunc("GET /search", searchHandler)
	mux.HandleFunc("GET /check", checkHandler)
	mux.HandleFunc("GET /api/memory", apiMemoryHandler)
	mux.Handle("GET /static/", staticHandler())
	// Пробы Kubernetes
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("GET /readyz", readyHandler)
	mux.HandleFunc("GET /metrics", metricsHandler)

	return logRequests(securityHeaders(mux))
}

// Стили пока встроены в шаблоны, поэтому для них разрешен inline.
// data: нужен для стрелки выпадающего списка
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// Отдает встроенные статические файлы
func staticHandler() http.Handler {
	files := http.FileServerFS(staticFS)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Списки каталогов не показываем
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	})
}

// Добавляет защитные заголовки ко всем ответам
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// В строке запроса внутренние адреса, не отдаем их сторонним хостам
		h.Set("Referrer-Policy", "no-referrer")
		// Скрипты только свои и только из файлов: даже пропущенный в разметку
		// пользовательский ввод не выполнится
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// Рендерит шаблон в буфер, чтобы при ошибке не отдать половину страницы
func renderTemplate(w http.ResponseWriter, name string, data any) {
	renderTemplateStatus(w, http.StatusOK, name, data)
}

func renderTemplateStatus(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		componentLogger("http").Error("cannot render template "+name, "error", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		// Обычно клиент просто закрыл соединение
		componentLogger("http").Debug("cannot write response", "error", err.Error())
	}
}

// Ссылка на задачу в Jira. Запрос экранируется здесь: html/template не знает,
// что базовый URL из окружения заканчивается путем или строкой запроса
func jiraLink(query string) string {
	base := os.Getenv("JIRA_URL")
	if base == "" {
		base = "https://jira.example.com/browse/"
	}
	return base + url.PathEscape(strings.ToUpper(strings.TrimSpace(query)))
}

// Похож ли запрос на номер задачи. Регистр не важен: "noc-2273" тоже задача
func isJiraQuery(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "NOC-")
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
	var matches []matchedRule

	for i := range state.PolicyRules {
		if isSearchMatch(state.PolicyRules[i], query) {
			matches = append(matches, matchedRule{rule: &state.PolicyRules[i]})
		}
	}

	return groupRules(matches)
}

// Проверяет совпадает ли правило с поисковым запросом
func isSearchMatch(rule PolicyRule, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))

	if prefix, ok := parsePrefix(query); ok {
		// Запрос с маской ищет правила, где записан именно этот префикс:
		// 10.1.1.5/32 не находит 10.1.1.0/24
		if strings.Contains(query, "/") {
			return rule.srcAddrs.hasPrefix(prefix) || rule.dstAddrs.hasPrefix(prefix)
		}
		// Адрес без маски ищет все сети, в которые он входит
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

// Загружает конфигурационные файлы и публикует новое состояние.
// Все подробности пишет в лог сама, вызывающему коду дублировать их не нужно
func loadConfigFiles() error {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	log := componentLogger("loader")
	start := time.Now()

	oldState := getState()
	aclFiles, confFiles := findFilterFiles()

	// Перезагрузка раз в две минуты обычно ничего не меняет. Сначала сравниваем
	// хеш файлов: разбор заново строит все состояние в памяти, и делать это
	// ради тех же данных незачем. На уровне info пишем только реальные изменения
	fingerprint, hashErr := fingerprintFiles(aclFiles, confFiles)
	if hashErr == nil && fingerprint == oldState.fingerprint {
		log.Debug("filters unchanged",
			"files", len(aclFiles)+len(confFiles),
			"duration_ms", time.Since(start).Milliseconds())
		reloadsUnchanged.Add(1)
		lastReloadOK.Store(time.Now().Unix())
		return nil
	}

	newState, loadErr := buildState(log, aclFiles, confFiles)
	// После ошибки хеш не запоминаем, чтобы следующая перезагрузка разобрала файлы снова
	if hashErr == nil && loadErr == nil {
		newState.fingerprint = fingerprint
	}
	oldHasData := len(oldState.PrefixLists) > 0 || len(oldState.PolicyRules) > 0

	// Если ни один файл не загрузился, оставляем старое состояние
	if len(newState.PrefixLists) == 0 && len(newState.PolicyRules) == 0 {
		log.Error("no filter data loaded, keeping previous state",
			"files", newState.files,
			"prefix_lists", len(oldState.PrefixLists),
			"rules", len(oldState.PolicyRules))
		reloadsFailed.Add(1)
		return errors.New("no data loaded from any file")
	}

	// Файл мог читаться в момент обновления репозитория. Частичные данные хуже
	// устаревших, поэтому при ошибке оставляем уже загруженное состояние
	if loadErr != nil && oldHasData {
		log.Error("filter reload finished with errors, keeping previous state",
			"error", loadErr.Error(),
			"prefix_lists", len(oldState.PrefixLists),
			"rules", len(oldState.PolicyRules))
		reloadsFailed.Add(1)
		return loadErr
	}

	duration := time.Since(start).Milliseconds()

	newState.loadedAt = time.Now()
	currentState.Store(newState)

	if loadErr != nil {
		reloadsFailed.Add(1)
	} else {
		reloadsChanged.Add(1)
		lastReloadOK.Store(newState.loadedAt.Unix())
	}

	msg := fmt.Sprintf("filters loaded: %d prefix lists, %d rules from %d files",
		len(newState.PrefixLists), len(newState.PolicyRules), newState.files)
	attrs := []any{
		"prefix_lists", len(newState.PrefixLists),
		"rules", len(newState.PolicyRules),
		"files", newState.files,
		"duration_ms", duration,
	}
	if loadErr != nil {
		log.Warn(msg+", some files failed", append(attrs, "error", loadErr.Error())...)
	} else {
		log.Info(msg, attrs...)
	}

	reportProblems(log, newState.problems)
	return loadErr
}

// О каких проблемах в данных уже сообщали. Защищено reloadMu
var reportedProblems = make(map[string]string)

// Пишет предупреждения о значениях, которые не удалось разобрать. Повторяет их,
// только когда набор изменился: иначе одно и то же шло бы в лог каждые две минуты
func reportProblems(log *slog.Logger, problems loadProblems) {
	kinds := []struct {
		name     string
		items    []string
		found    string
		resolved string
	}{
		{"missing_prefix_list", problems.missingLists,
			"%d prefix lists are referenced but not defined, terms using them match nothing",
			"all referenced prefix lists are defined again"},
		{"invalid_prefix", problems.invalidPrefixes,
			"%d prefixes could not be parsed, they are ignored when matching",
			"all prefixes are parsed again"},
		{"invalid_port", problems.invalidPorts,
			"%d ports could not be parsed, terms using them match any port only partially",
			"all ports are parsed again"},
	}

	for _, kind := range kinds {
		signature := strings.Join(kind.items, "\n")
		if reportedProblems[kind.name] == signature {
			continue
		}
		reportedProblems[kind.name] = signature

		if len(kind.items) == 0 {
			log.Info(kind.resolved, "problem", kind.name)
			continue
		}
		// Сами значения только в поле: среди них есть адреса
		log.Warn(fmt.Sprintf(kind.found, len(kind.items)),
			"problem", kind.name,
			"count", len(kind.items),
			"sample", logSample(kind.items))
	}
}

// Находит файлы с префикс-листами и с фильтрами
func findFilterFiles() (aclFiles, confFiles []string) {
	// Ссылку на каталог разрешаем один раз за перезагрузку. Если git-sync
	// переключит версию посреди чтения, хеш и разбор все равно пройдут по одной
	// ревизии, а не по смеси двух
	dir, err := filepath.EvalSymlinks(filtersDir)
	if err != nil {
		// Каталога еще нет: файлов не найдем, загрузчик сообщит об этом сам
		dir = filtersDir
	}

	// Шаблоны файлов которые парсим
	aclPatterns := []string{
		filepath.Join(dir, "jcore*.acl.txt"),
	}

	confPatterns := []string{
		filepath.Join(dir, "jcore*.acl.conf.txt"),
	}

	for _, pattern := range aclPatterns {
		files, _ := filepath.Glob(pattern)
		aclFiles = append(aclFiles, files...)
	}

	for _, pattern := range confPatterns {
		files, _ := filepath.Glob(pattern)
		confFiles = append(confFiles, files...)
	}

	// Убираем дубликаты
	return uniqueFiles(aclFiles), uniqueFiles(confFiles)
}

// Считает хеш имен и содержимого файлов. Файлы читаются потоком, без загрузки в память.
// В хеш идет только имя файла без каталога: у git-sync каталог версии меняется
// с каждым коммитом, даже если сами фильтры остались прежними
func fingerprintFiles(fileLists ...[]string) (string, error) {
	hash := sha256.New()

	for _, files := range fileLists {
		for _, name := range files {
			io.WriteString(hash, filepath.Base(name)+"\n")

			file, err := os.Open(name)
			if err != nil {
				return "", err
			}
			_, err = io.Copy(hash, file)
			file.Close()
			if err != nil {
				return "", err
			}
			io.WriteString(hash, "\n")
		}
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Собирает состояние из файлов, не трогая опубликованное
func buildState(log *slog.Logger, allAclFiles, allConfFiles []string) (*AppState, error) {
	state := newAppState()
	state.files = len(allAclFiles) + len(allConfFiles)

	log.Debug("filter files found",
		"acl_files", len(allAclFiles),
		"conf_files", len(allConfFiles))

	var errs []error

	// Парсим ACL файлы
	for _, aclFile := range allAclFiles {
		if err := parsePrefixLists(state, aclFile); err != nil {
			log.Warn("cannot read prefix list file "+filepath.Base(aclFile), "filter_file", aclFile, "error", err.Error())
			errs = append(errs, fmt.Errorf("%s: %w", aclFile, err))
		}
	}

	// Парсим CONF файлы
	for _, confFile := range allConfFiles {
		if err := parsePolicyRules(state, confFile); err != nil {
			log.Warn("cannot read filter file "+filepath.Base(confFile), "filter_file", confFile, "error", err.Error())
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

// Автоматически перезагружает конфиги по таймеру, пока контекст не отменен
func autoReloadConfigs(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reloadSafely()
		}
	}
}

// Перезагрузка с перехватом паники: сбой разбора не должен ронять сервис,
// а стектрейс должен попасть в лог одним событием
func reloadSafely() {
	defer func() {
		if recovered := recover(); recovered != nil {
			stack := string(debug.Stack())
			if len(stack) > maxStacktraceLen {
				stack = stack[:maxStacktraceLen] + "..."
			}
			componentLogger("loader").Error("panic while reloading filters",
				"error", truncateLogValue(fmt.Sprint(recovered)),
				"stacktrace", stack)
		}
	}()

	// Результат и ошибки загрузчик пишет в лог сам
	_ = loadConfigFiles()
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
				Source:     filepath.Base(filename),
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

	state.problems = loadProblems{
		missingLists:    sortedKeys(missing),
		invalidPrefixes: sortedKeys(invalid),
		invalidPorts:    sortedKeys(invalidPorts),
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
		DataChanged string
	}{
		DataChanged: dataChangedText(state),
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

	state := getState()
	results := searchRulesWithGrouping(state, query)
	addLogString(r, "query", query)
	addLogAttrs(r, slog.Int("matches", len(results)))

	data := struct {
		Query        string
		MatchedRules []GroupedRule
		MemoryUsage  string
		SearchTime   string
		DataChanged  string
	}{
		DataChanged:  dataChangedText(state),
		Query:        query,
		MatchedRules: results,
		MemoryUsage:  getMemoryUsage(),
		SearchTime:   time.Now().Format("15:04:05"),
	}

	renderTemplate(w, "results.html", data)
}

// Когда сервис последний раз загрузил изменившиеся фильтры, для подвала страниц.
// Если файлы перестанут обновляться, по этой строке видно, что данные старые
func dataChangedText(state *AppState) string {
	if state.loadedAt.IsZero() {
		return "not loaded"
	}
	return state.loadedAt.Format("2006-01-02 15:04 MST")
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

// Liveness: процесс жив и отвечает на запросы
func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeProbe(w, http.StatusOK, "ok")
}

// Readiness: фильтры загружены, сервису есть что отвечать. Пока данных нет,
// проверка доступа показывала бы "доступ закрыт" для любого запроса
func readyHandler(w http.ResponseWriter, r *http.Request) {
	state := getState()
	if len(state.PrefixLists) == 0 && len(state.PolicyRules) == 0 {
		writeProbe(w, http.StatusServiceUnavailable, "filters are not loaded")
		return
	}
	writeProbe(w, http.StatusOK, "ok")
}

func writeProbe(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintln(w, text)
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
		Src:         src,
		Dst:         dst,
		Port:        port,
		Filter:      filter,
		AllFilters:  getAllFilterNames(state),
		DataChanged: dataChangedText(state),
	}

	// Если все поля пустые, просто показываем форму
	if src == "" && dst == "" && port == "" {
		renderTemplate(w, "check.html", data)
		return
	}

	// Что проверяли и чем закончилось, попадает в access-лог отдельными полями
	addLogString(r, "src", src)
	addLogString(r, "dst", dst)
	addLogString(r, "port", port)
	addLogString(r, "filter", filter)

	query, err := parseAccessQuery(src, dst, port)
	if err != nil {
		addLogAttrs(r, slog.String("result", "invalid"))
		data.Error = err.Error()
		renderTemplateStatus(w, http.StatusBadRequest, "check.html", data)
		return
	}

	// Ищем правила в выбранном фильтре или во всех
	result := checkAccess(state, query, filter)

	data.Checked = true
	data.MatchingRules = result.Allowed
	data.BlockingRules = result.Blocked

	// Доступ открыт, если хотя бы один разрешающий терм ничем не перекрыт.
	// Если перед каждым есть запрещающий терм, который может сработать раньше,
	// доступ открыт только частично
	for _, rule := range result.Allowed {
		if len(rule.ShadowedBy) == 0 {
			data.AccessGranted = true
			break
		}
	}
	data.AccessPartial = len(result.Allowed) > 0 && !data.AccessGranted

	outcome := "denied"
	if data.AccessGranted {
		outcome = "open"
	} else if data.AccessPartial {
		outcome = "partial"
	}
	addLogAttrs(r, slog.String("result", outcome), slog.Int("matches", len(result.Allowed)))

	renderTemplate(w, "check.html", data)
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
