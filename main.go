package main

import (
    "bufio"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "text/template"
    "runtime"
    "time"
    "sync"
    "sort"
    "path/filepath"
    "strconv"
    "net"
)

// Префикс-лист Juniper
type PrefixList struct {
    Name    string
    Prefixes []string
}

// Term политики Juniper
type PolicyTerm struct {
    Name              string
    SourceAddresses  []string
    DestinationAddresses []string
    SourcePrefixLists []string
    DestinationPrefixLists []string
    Protocol         string
    SourcePorts     []string
    DestinationPorts []string
    Action           string
    Counter          string
}

// Полное правило
type PolicyRule struct {
    FilterName string
    Term PolicyTerm
    ResolvedSourcePrefixes []string // Разрешенные префиксы из префикс-листов
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
    TermName                  string
    SourcePrefixes           []string
    DestinationPrefixes      []string
    SourcePrefixLists        []string
    DestinationPrefixLists   []string
    Protocol                 string
    SourcePorts             []string
    DestinationPorts        []string
    Action                   string
    Filters                  []string // Список фильтров, где встречается это правило
}

// Данные для страницы проверки
type CheckPageData struct {
    Src            string
    Dst            string
    Port           string
    Checked        bool
    AccessGranted  bool
    AccessPartial  bool
    MatchingRules  []GroupedRule
}

var startTime time.Time
var appState AppState
var mu sync.Mutex
var lastModified time.Time

func main() {
    startTime = time.Now()

    // Инициализация состояния
    appState = AppState{
        PrefixLists: make(map[string][]string),
        PolicyRules: []PolicyRule{},
    }

    // Парсинг файлов
    loadConfigFiles()
    // Автообновление каждые 2 минут
    go autoReloadConfigs(2 * time.Minute)

    // Разворачивание префикс-листов
    resolvePrefixLists()

    // Настройка HTTP-обработчиков
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/search", searchHandler)
    http.HandleFunc("/check", checkHandler)
    http.HandleFunc("/api/memory", apiMemoryHandler)

    log.Printf("✅ Server started on http://localhost:8080") // TODO: Вынести адрес и порт в конфиг
    log.Println("📊 Prefix lists loaded:", len(appState.PrefixLists))
    log.Println("📊 Policy rules loaded:", len(appState.PolicyRules))

    if err := http.ListenAndServe(":8080", nil); err != nil { // TODO: Вынести порт в конфиг
        log.Printf("❌ Server startup error: %v\n", err)
    }
}

// Ищет правила и группирует их
func searchRulesWithGrouping(query string) []GroupedRule {
    groupedRules := make(map[string]*GroupedRule)
    
    for _, rule := range appState.PolicyRules {
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
                TermName:                rule.Term.Name,
                SourcePrefixes:         uniqueStrings(rule.ResolvedSourcePrefixes),
                DestinationPrefixes:    uniqueStrings(rule.ResolvedDestinationPrefixes),
                SourcePrefixLists:      uniqueStrings(rule.Term.SourcePrefixLists),
                DestinationPrefixLists: uniqueStrings(rule.Term.DestinationPrefixLists),
                Protocol:               rule.Term.Protocol,
                SourcePorts:           uniqueStrings(rule.Term.SourcePorts),
                DestinationPorts:      uniqueStrings(rule.Term.DestinationPorts),
                Action:                 rule.Term.Action,
                Filters:               []string{rule.FilterName},
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

// Загружает конфигурационные файлы
func loadConfigFiles() error {
    mu.Lock()
    defer mu.Unlock()
    
    log.Println("🔄 Loading configuration files...")
    
    // Сохраняем текущее состояние на случай ошибки
    oldState := appState
    
    // Создаем новое состояние
    newState := AppState{
        PrefixLists: make(map[string][]string),
        PolicyRules: []PolicyRule{},
    }
    
    // Используем новое состояние
    appState = newState
    
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
    
    // Парсим ACL файлы
    for _, aclFile := range allAclFiles {
        if err := parsePrefixLists(aclFile); err != nil {
            log.Printf("⚠️ ACL file error %s: %v", aclFile, err)
        }
    }
    
    // Парсим CONF файлы
    for _, confFile := range allConfFiles {
        if err := parsePolicyRules(confFile); err != nil {
            log.Printf("⚠️ CONF file error %s: %v", confFile, err)
        }
    }
    
    // Разворачивает префикс-листы
    resolvePrefixLists()
    lastModified = time.Now()
    
    log.Printf("✅ Loaded: %d prefix lists, %d rules", 
        len(appState.PrefixLists), len(appState.PolicyRules))
    
    // Если нужно восстановить старое состояние при ошибке
    // (например, если ни один файл не загрузился)
    if len(appState.PrefixLists) == 0 && len(appState.PolicyRules) == 0 {
        log.Println("⚠️ No data loaded, restoring old state")
        appState = oldState
        return fmt.Errorf("No data loaded from any file")
    }
    
    return nil
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
func parsePrefixLists(filename string) error {
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
                
                appState.PrefixLists[listName] = append(appState.PrefixLists[listName], prefix)
            }
        }
    }

    return scanner.Err()
}

// Парсит файл с политиками
func parsePolicyRules(filename string) error {
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
                        appState.PolicyRules = append(appState.PolicyRules, PolicyRule{
                            FilterName: currentFilter,
                            Term: *currentTerm,
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
                appState.PolicyRules = append(appState.PolicyRules, PolicyRule{
                    FilterName: currentFilter,
                    Term: *currentTerm,
                })
            }
            termName := strings.TrimPrefix(line, "term ")
            termName = strings.TrimSuffix(termName, " {")
            currentTerm = &PolicyTerm{
                Name: termName,
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
        appState.PolicyRules = append(appState.PolicyRules, PolicyRule{
            FilterName: currentFilter,
            Term: *currentTerm,
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
        term.DestinationPorts = append(term.DestinationPorts, ports)
        return
    }
}

// Парсит секцию "then"
func parseThenSection(line string, term *PolicyTerm) {
    if strings.HasPrefix(line, "count ") {
        term.Counter = strings.TrimSuffix(strings.TrimPrefix(line, "count "), ";")
    } else if strings.HasPrefix(line, "accept") {
        term.Action = "accept"
        // Для accept не нужно обрезать ";", так как префикс уже совпал
    } else if strings.HasPrefix(line, "reject") || strings.HasPrefix(line, "deny") {
        term.Action = "reject"
        // Для reject/deny не нужно обрезать ";", так как префикс уже совпал
    }
}

// Разворачивает префикс-листы в конкретные префиксы
func resolvePrefixLists() {
    for i, rule := range appState.PolicyRules {
        var resolvedSourcePrefixes []string
        var resolvedDestinationPrefixes []string
        
        // Добавляем прямые source-address
        resolvedSourcePrefixes = append(resolvedSourcePrefixes, rule.Term.SourceAddresses...)
        
        // Разворачивает source префикс-листы
        for _, listName := range rule.Term.SourcePrefixLists {
            if prefixes, exists := appState.PrefixLists[listName]; exists {
                resolvedSourcePrefixes = append(resolvedSourcePrefixes, prefixes...)
            }
        }
        
        // Добавляем прямые destination-address
        resolvedDestinationPrefixes = append(resolvedDestinationPrefixes, rule.Term.DestinationAddresses...)
        
        // Разворачивает destination префикс-листы
        for _, listName := range rule.Term.DestinationPrefixLists {
            if prefixes, exists := appState.PrefixLists[listName]; exists {
                resolvedDestinationPrefixes = append(resolvedDestinationPrefixes, prefixes...)
            }
        }
        
        appState.PolicyRules[i].ResolvedSourcePrefixes = resolvedSourcePrefixes
        appState.PolicyRules[i].ResolvedDestinationPrefixes = resolvedDestinationPrefixes
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
    tmpl := template.New("index.html").Funcs(template.FuncMap{
        "add": func(a, b int) int { return a + b },
    })
    
    tmpl, err := tmpl.ParseFiles("templates/index.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    data := struct {
        Stats       AppStats
        SampleRules []PolicyRule
    }{
        Stats: AppStats{
            PrefixListCount: len(appState.PrefixLists),
            RuleCount:       len(appState.PolicyRules),
            MemoryUsage:     getMemoryUsage(),
            Goroutines:      runtime.NumGoroutine(),
            Uptime:          getUptime(),
        },
    }

    // Берем последние 3 правила для примера
    if len(appState.PolicyRules) > 3 {
        data.SampleRules = appState.PolicyRules[len(appState.PolicyRules)-3:]
    } else {
        data.SampleRules = appState.PolicyRules
    }
    
    tmpl.Execute(w, data)
}

// Обработчик поиска
func searchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    if query == "" {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    
    results := searchRulesWithGrouping(query)
    
    tmpl := template.New("results.html").Funcs(template.FuncMap{
        "add": func(a, b int) int { return a + b },
        "join": func(items []string, sep string) string {
            return strings.Join(items, sep)
        },
    })
    
    tmpl, err := tmpl.ParseFiles("templates/results.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
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
    
    tmpl.Execute(w, data)
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
    len(appState.PrefixLists),
    len(appState.PolicyRules))
}

// checkHandler обрабатывает проверку доступа
func checkHandler(w http.ResponseWriter, r *http.Request) {
    src := r.URL.Query().Get("src")
    dst := r.URL.Query().Get("dst")
    port := r.URL.Query().Get("port")
    
    tmpl := template.New("check.html").Funcs(template.FuncMap{
        "add": func(a, b int) int { return a + b },
        "join": func(items []string, sep string) string {
            return strings.Join(items, sep)
        },
    })
    
    tmpl, err := tmpl.ParseFiles("templates/check.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    data := CheckPageData{
        Src:   src,
        Dst:   dst,
        Port:  port,
    }
    
    // Если все поля пустые, просто показываем форму
    if src == "" && dst == "" && port == "" {
        tmpl.Execute(w, data)
        return
    }
    
    // Ищем правила
    rules := checkAccess(src, dst, port)
    data.Checked = true
    data.MatchingRules = rules
    
    // Определяем статус доступа
    if len(rules) > 0 {
        data.AccessGranted = true
    }
    
    tmpl.Execute(w, data)
}

// Проверяет доступ по всем параметрам и возвращает сгруппированные правила
func checkAccess(src, dst, port string) []GroupedRule {
    groupedRules := make(map[string]*GroupedRule)
    
    for _, rule := range appState.PolicyRules {
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
                TermName:                rule.Term.Name,
                SourcePrefixes:         uniqueStrings(rule.ResolvedSourcePrefixes),
                DestinationPrefixes:    uniqueStrings(rule.ResolvedDestinationPrefixes),
                SourcePrefixLists:      uniqueStrings(rule.Term.SourcePrefixLists),
                DestinationPrefixLists: uniqueStrings(rule.Term.DestinationPrefixLists),
                Protocol:               rule.Term.Protocol,
                SourcePorts:           uniqueStrings(rule.Term.SourcePorts),
                DestinationPorts:      uniqueStrings(rule.Term.DestinationPorts),
                Action:                 rule.Term.Action,
                Filters:               []string{rule.FilterName},
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
        // Если в правиле нет source префиксов, значит правило не ограничивает source
        if len(rule.ResolvedSourcePrefixes) == 0 {
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
        // Если в правиле нет destination префиксов, значит правило не ограничивает destination
        if len(rule.ResolvedDestinationPrefixes) == 0 {
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
    
    // Проверяем диапазоны портов
    if strings.Contains(rulePort, "-") {
        parts := strings.Split(rulePort, "-")
        if len(parts) == 2 {
            start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
            end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
            if err1 == nil && err2 == nil {
                queryNum, err := strconv.Atoi(queryPort)
                if err == nil && queryNum >= start && queryNum <= end {
                    return true
                }
            }
        }
    }
    
    // Проверяем если запрос - диапазон, а правило - одиночный порт
    if strings.Contains(queryPort, "-") {
        parts := strings.Split(queryPort, "-")
        if len(parts) == 2 {
            start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
            end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
            ruleNum, err3 := strconv.Atoi(rulePort)
            if err1 == nil && err2 == nil && err3 == nil {
                // Если правило покрывает хотя бы часть диапазона
                if ruleNum >= start && ruleNum <= end {
                    return true
                }
            }
        }
    }
    
    // Специальные случаи
    if rulePort == "any" || rulePort == "all" || rulePort == "*" {
        return true
    }
    
    // Проверяем если правило содержит запрос как подстроку
    if strings.Contains(ruleLower, queryLower) {
        return true
    }
    
    return false
}
