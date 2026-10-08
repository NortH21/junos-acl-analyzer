package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Пишет конфиги во временную директорию и загружает их так же, как приложение
func loadTestConfig(t *testing.T, acl, conf string) {
	t.Helper()
	loadTestFiles(t, map[string]string{
		"jcore1.acl.txt":      acl,
		"jcore1.acl.conf.txt": conf,
	})
}

// То же для произвольного набора файлов в jcore-filters
func loadTestFiles(t *testing.T, files map[string]string) {
	t.Helper()

	dir := t.TempDir()
	filters := filepath.Join(dir, "jcore-filters")
	if err := os.Mkdir(filters, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(filters, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Chdir(dir)
	currentState.Store(newAppState())
	reportedProblems = make(map[string]string)
	if err := loadConfigFiles(); err != nil {
		t.Fatalf("loadConfigFiles: %v", err)
	}
}

// Возвращает action терма по имени
func termAction(t *testing.T, name string) string {
	t.Helper()
	for _, rule := range getState().PolicyRules {
		if rule.Term.Name == name {
			return rule.Term.Action
		}
	}
	t.Fatalf("term %q not found", name)
	return ""
}

// Возвращает разобранный term по имени
func findTerm(t *testing.T, name string) PolicyTerm {
	t.Helper()
	for _, rule := range getState().PolicyRules {
		if rule.Term.Name == name {
			return rule.Term
		}
	}
	t.Fatalf("term %q not found", name)
	return PolicyTerm{}
}

func mustQuery(t *testing.T, src, dst, port string) accessQuery {
	t.Helper()
	query, err := parseAccessQuery(src, dst, port)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

// Возвращает разрешающие термы для запроса. Некорректный запрос не разрешает ничего
func allowedRules(t *testing.T, src, dst, port string) []GroupedRule {
	t.Helper()
	query, err := parseAccessQuery(src, dst, port)
	if err != nil {
		return nil
	}
	return checkAccess(getState(), query, "").Allowed
}

func hasTerm(rules []GroupedRule, name string) bool {
	for _, rule := range rules {
		if rule.TermName == name {
			return true
		}
	}
	return false
}

const testACL = `set policy-options prefix-list WEB 10.1.1.0/24
set policy-options prefix-list DB 10.2.2.0/24
`

func TestParseThenActions(t *testing.T) {
	loadTestConfig(t, testACL, `firewall {
    family inet {
        filter TEST-IN {
            term T-ACCEPT {
                then {
                    count c1;
                    accept;
                }
            }
            term T-DISCARD {
                then {
                    count c2;
                    discard;
                }
            }
            term T-REJECT {
                then {
                    reject tcp-reset;
                }
            }
            term T-INLINE-DISCARD {
                from {
                    protocol udp;
                }
                then discard;
            }
            term T-INLINE-ACCEPT {
                then accept;
            }
            term T-NEXT {
                then {
                    count c3;
                    next term;
                }
            }
            term T-COUNT-ONLY {
                then {
                    count c4;
                }
            }
        }
    }
}
`)

	want := map[string]string{
		"T-ACCEPT":         "accept",
		"T-DISCARD":        "discard",
		"T-REJECT":         "reject",
		"T-INLINE-DISCARD": "discard",
		"T-INLINE-ACCEPT":  "accept",
		"T-NEXT":           "next",
		"T-COUNT-ONLY":     "accept", // в Junos терм без терминирующего действия принимает пакет
	}
	if len(getState().PolicyRules) != len(want) {
		t.Fatalf("parsed %d terms, want %d", len(getState().PolicyRules), len(want))
	}
	for name, action := range want {
		if got := termAction(t, name); got != action {
			t.Errorf("term %s: action = %q, want %q", name, got, action)
		}
	}
}

func TestDiscardTermDoesNotGrantAccess(t *testing.T) {
	loadTestConfig(t, testACL, `filter TEST-IN {
    term BLOCK-WEB {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then {
            discard;
        }
    }
}
`)

	if rules := allowedRules(t, "10.1.1.5", "", ""); len(rules) != 0 {
		t.Errorf("discard term reported as allowing access: %+v", rules)
	}
}

func TestUnresolvedPrefixListMatchesNothing(t *testing.T) {
	loadTestConfig(t, testACL, `filter TEST-IN {
    term MISSING-SRC {
        from {
            source-prefix-list {
                NO-SUCH-LIST;
            }
            destination-prefix-list {
                DB;
            }
        }
        then accept;
    }
    term MISSING-DST {
        from {
            source-prefix-list {
                WEB;
            }
            destination-prefix-list {
                NO-SUCH-LIST;
            }
        }
        then accept;
    }
    term ANY-SRC {
        from {
            destination-prefix-list {
                DB;
            }
        }
        then accept;
    }
}
`)

	rules := allowedRules(t, "8.8.8.8", "10.2.2.2", "")
	if hasTerm(rules, "MISSING-SRC") {
		t.Error("term with undefined source prefix-list matched an arbitrary source")
	}
	if !hasTerm(rules, "ANY-SRC") {
		t.Error("term without source conditions must match any source")
	}

	if rules := allowedRules(t, "10.1.1.5", "8.8.8.8", ""); hasTerm(rules, "MISSING-DST") {
		t.Error("term with undefined destination prefix-list matched an arbitrary destination")
	}
}

// Выполняет GET-запрос к приложению и возвращает ответ
func get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestUserInputIsEscaped(t *testing.T) {
	loadTestConfig(t, testACL, `filter TEST-IN {
    term T1 {
        then accept;
    }
}
`)

	const payload = `"><script>alert(1)</script>`
	const encoded = "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E"

	targets := []string{
		"/search?q=" + encoded,
		"/check?src=" + encoded,
		"/check?dst=" + encoded,
		"/check?port=" + encoded,
		"/check?src=10.1.1.1&filter=" + encoded,
	}
	for _, target := range targets {
		rec := get(t, target)
		// Некорректный адрес или порт возвращает 400 вместе с формой
		if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), payload) || strings.Contains(rec.Body.String(), "<script>alert(1)") {
			t.Errorf("%s: user input rendered without escaping", target)
		}
	}
}

func TestExternalLinksAreEscaped(t *testing.T) {
	loadTestConfig(t, testACL, `filter TEST-IN {
    term T1 {
        then accept;
    }
}
`)
	t.Setenv("NETBOX_URL", "https://netbox.example.com/search/?q=")
	t.Setenv("JIRA_URL", "https://jira.example.com/browse/")

	body := get(t, "/search?q=10.1.1.0%2F24%26x%3D%22y").Body.String()
	if !strings.Contains(body, `href="https://netbox.example.com/search/?q=10.1.1.0%2F24%26x%3D%22y"`) {
		t.Errorf("netbox link is not URL-escaped:\n%s", linkLines(body))
	}

	body = get(t, "/search?q=NOC-1").Body.String()
	if !strings.Contains(body, `href="https://jira.example.com/browse/NOC-1"`) {
		t.Errorf("jira link missing:\n%s", linkLines(body))
	}
}

func linkLines(body string) string {
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "href=\"http") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return strings.Join(lines, "\n")
}

func TestSecurityHeaders(t *testing.T) {
	loadTestConfig(t, testACL, "filter F {\n    term T1 {\n        then accept;\n    }\n}\n")

	headers := get(t, "/").Header()
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": contentSecurityPolicy,
	}
	for name, value := range want {
		if got := headers.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestPagesRender(t *testing.T) {
	loadTestConfig(t, testACL, `filter TEST-IN {
    term NOC-1 {
        from {
            source-prefix-list {
                WEB;
            }
            destination-prefix-list {
                DB;
            }
            protocol tcp;
            destination-port [ 443 8080-8090 ];
        }
        then accept;
    }
}
`)

	pages := map[string]string{
		"/":                    "Junos ACL Analyzer",
		"/check":               `<option value="TEST-IN"`,
		"/check?src=10.1.1.5":  "Term: NOC-1",
		"/search?q=WEB":        "Term: NOC-1",
		"/search?q=10.2.2.200": "10.2.2.0/24",
		"/search?q=nothing":    "Nothing found",
		"/api/memory":          `"rules": 1`,
	}
	for target, marker := range pages {
		rec := get(t, target)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", target, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), marker) {
			t.Errorf("%s: %q not found in response", target, marker)
		}
	}
}

func TestReloadIsAtomic(t *testing.T) {
	var acl, conf strings.Builder
	conf.WriteString("filter F {\n")
	const terms = 500
	for i := 0; i < terms; i++ {
		fmt.Fprintf(&acl, "set policy-options prefix-list L%d 10.%d.%d.0/24\n", i, i/250, i%250)
		fmt.Fprintf(&conf, "term T%d {\nfrom {\nsource-prefix-list {\nL%d;\n}\n}\nthen {\naccept;\n}\n}\n", i, i)
	}
	conf.WriteString("}\n")
	loadTestConfig(t, acl.String(), conf.String())

	// Запускать с -race: читатели не должны видеть пустое или частичное состояние
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < 20; i++ {
			if err := loadConfigFiles(); err != nil {
				t.Errorf("reload: %v", err)
			}
		}
	}()

	for {
		select {
		case <-done:
			wg.Wait()
			return
		default:
		}

		state := getState()
		if got := len(state.PolicyRules); got != terms {
			t.Fatalf("reader saw %d rules during reload, want %d", got, terms)
		}
		// Все термы ограничены по source, поэтому посторонний адрес не должен подойти
		if rules := checkAccess(state, mustQuery(t, "8.8.8.8", "", ""), "").Allowed; len(rules) != 0 {
			t.Fatalf("reader saw %d unresolved rules during reload", len(rules))
		}
		if rules := checkAccess(state, mustQuery(t, "10.0.7.9", "", ""), "").Allowed; len(rules) != 1 {
			t.Fatalf("reader saw %d matching rules during reload, want 1", len(rules))
		}
	}
}

func TestFailedReloadKeepsOldState(t *testing.T) {
	loadTestConfig(t, testACL, "filter F {\n    term T1 {\n        then accept;\n    }\n}\n")

	// Каталог с файлами исчез (например, репозиторий переключают)
	if err := os.RemoveAll("jcore-filters"); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFiles(); err == nil {
		t.Error("reload without files must return an error")
	}
	if got := len(getState().PolicyRules); got != 1 {
		t.Errorf("old state lost after failed reload: %d rules", got)
	}

	// Файл правил не читается, а префикс-листы на месте
	if err := os.MkdirAll(filepath.Join("jcore-filters", "jcore1.acl.conf.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("jcore-filters", "jcore1.acl.txt"), []byte(testACL), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFiles(); err == nil {
		t.Error("reload with an unreadable file must return an error")
	}
	if got := len(getState().PolicyRules); got != 1 {
		t.Errorf("partial state published after failed reload: %d rules", got)
	}
}

func TestParseFilterStructure(t *testing.T) {
	loadTestConfig(t, testACL, `firewall {
    family inet {
        filter FIRST {
            /* комментарий Junos */
            term FULL {
                from {
                    source-address {
                        10.0.0.0/8;
                        10.9.0.0/16 except;
                    }
                    destination-address {
                        192.168.1.1/32;
                    }
                    source-prefix-list {
                        WEB;
                    }
                    destination-prefix-list {
                        DB;
                    }
                    address {
                        172.16.0.0/12;
                    }
                    protocol tcp;
                    source-port 1024-65535;
                    destination-port [ 80 443 8080-8090 ];
                    tcp-established;
                }
                then {
                    policer P1;
                    count c1;
                    accept;
                }
            }
            inactive: term DISABLED {
                from {
                    source-address {
                        1.1.1.1/32;
                    }
                }
                then accept;
            }
            term INLINE {
                from protocol udp;
                then discard;
            }
        }
        filter SECOND {
            term ONLY {
                then accept;
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input FIRST;
                }
            }
        }
    }
}
`)

	rules := getState().PolicyRules
	var got []string
	for _, rule := range rules {
		got = append(got, rule.FilterName+"/"+rule.Term.Name)
	}
	want := []string{"FIRST/FULL", "FIRST/INLINE", "SECOND/ONLY"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("parsed terms %v, want %v", got, want)
	}

	full := findTerm(t, "FULL")
	checks := map[string][2]string{
		"source addresses":      {strings.Join(full.SourceAddresses, ","), "10.0.0.0/8,10.9.0.0/16 except"},
		"destination addresses": {strings.Join(full.DestinationAddresses, ","), "192.168.1.1/32"},
		"source lists":          {strings.Join(full.SourcePrefixLists, ","), "WEB"},
		"destination lists":     {strings.Join(full.DestinationPrefixLists, ","), "DB"},
		"protocol":              {full.Protocol, "tcp"},
		"source ports":          {strings.Join(full.SourcePorts, ","), "1024-65535"},
		"destination ports":     {strings.Join(full.DestinationPorts, ","), "80,443,8080-8090"},
		"other conditions":      {strings.Join(full.OtherConditions, ","), "address 172.16.0.0/12,tcp-established"},
		"action":                {full.Action, "accept"},
		"counter":               {full.Counter, "c1"},
	}
	for name, check := range checks {
		if check[0] != check[1] {
			t.Errorf("%s = %q, want %q", name, check[0], check[1])
		}
	}

	inline := findTerm(t, "INLINE")
	if inline.Protocol != "udp" || inline.Action != "discard" {
		t.Errorf("inline term parsed as protocol=%q action=%q", inline.Protocol, inline.Action)
	}
}

func TestParsePrefixListLines(t *testing.T) {
	loadTestConfig(t, `# комментарий
set policy-options prefix-list WEB 10.1.1.0/24
set policy-options prefix-list WEB 10.1.2.0/24
set groups G1 policy-options prefix-list GROUPED 10.3.3.0/24
set firewall family inet filter F term T from source-prefix-list WEB
set policy-options prefix-list EMPTY
`, "filter F {\n    term T1 {\n        then accept;\n    }\n}\n")

	lists := getState().PrefixLists
	if got := strings.Join(lists["WEB"], ","); got != "10.1.1.0/24,10.1.2.0/24" {
		t.Errorf("WEB = %q", got)
	}
	if got := strings.Join(lists["GROUPED"], ","); got != "10.3.3.0/24" {
		t.Errorf("GROUPED = %q", got)
	}
	if len(lists) != 2 {
		t.Errorf("unexpected prefix lists parsed: %v", lists)
	}
}

const addressTestConf = `filter TEST-IN {
    term TO-DB {
        from {
            source-prefix-list {
                WEB;
            }
            destination-prefix-list {
                DB;
            }
        }
        then accept;
    }
    term BARE-HOST {
        from {
            source-address {
                192.168.50.7;
            }
        }
        then accept;
    }
    term WITH-EXCEPT {
        from {
            source-address {
                172.16.0.0/12;
                172.16.5.0/24 except;
            }
        }
        then accept;
    }
    term BAD-PREFIX {
        from {
            source-address {
                not-an-address;
            }
        }
        then accept;
    }
}
`

func TestCheckAccessAddresses(t *testing.T) {
	loadTestConfig(t, testACL, addressTestConf)

	tests := []struct {
		src, dst string
		term     string
		want     bool
	}{
		{"10.1.1.5", "10.2.2.2", "TO-DB", true},
		{"10.1.1.5/32", "10.2.2.2/32", "TO-DB", true},
		{"10.1.1.128/25", "10.2.2.0/25", "TO-DB", true}, // подсеть разрешенной сети
		{"10.1.1.0/24", "10.2.2.0/24", "TO-DB", true},
		{"10.1.2.5", "10.2.2.2", "TO-DB", false},
		{"10.1.1.5", "10.2.3.2", "TO-DB", false},
		{"garbage", "10.2.2.2", "TO-DB", false},
		{"192.168.50.7", "", "BARE-HOST", true}, // адрес в правиле без маски
		{"192.168.50.8", "", "BARE-HOST", false},
		{"172.16.1.1", "", "WITH-EXCEPT", true},
		{"172.16.5.9", "", "WITH-EXCEPT", false},
		{"8.8.8.8", "", "BAD-PREFIX", false},
	}
	for _, tt := range tests {
		rules := allowedRules(t, tt.src, tt.dst, "")
		if got := hasTerm(rules, tt.term); got != tt.want {
			t.Errorf("src=%q dst=%q: term %s matched = %v, want %v", tt.src, tt.dst, tt.term, got, tt.want)
		}
	}
}

func TestSearch(t *testing.T) {
	loadTestConfig(t, testACL, addressTestConf)

	tests := []struct {
		query string
		term  string
		want  bool
	}{
		{"10.1.1.5", "TO-DB", true},
		{"10.1.1.5/32", "TO-DB", true},
		{"10.2.2.0/24", "TO-DB", true},
		{"10.2.0.0/16", "TO-DB", true}, // сеть находит префиксы внутри себя
		{"10.3.0.0/16", "TO-DB", false},
		{"0.1.1.5", "TO-DB", false},
		{"10.1.", "TO-DB", true},
		{"0.1.", "TO-DB", false}, // раньше находилось подстрокой
		{"web", "TO-DB", true},
		{"to-db", "TO-DB", true},
		{"172.16.5.1", "WITH-EXCEPT", true}, // except тоже часть правила
		{"192.168.50.7", "BARE-HOST", true},
	}
	for _, tt := range tests {
		rules := searchRulesWithGrouping(getState(), tt.query)
		if got := hasTerm(rules, tt.term); got != tt.want {
			t.Errorf("search %q: term %s found = %v, want %v", tt.query, tt.term, got, tt.want)
		}
	}
}

func TestCheckAccessPorts(t *testing.T) {
	loadTestConfig(t, testACL, `filter TEST-IN {
    term WEB-PORTS {
        from {
            destination-prefix-list {
                DB;
            }
            protocol tcp;
            destination-port [ http https 8080-8090 ];
        }
        then accept;
    }
    term SINGLE-PORT {
        from {
            destination-prefix-list {
                DB;
            }
            destination-port ssh;
        }
        then accept;
    }
}
`)

	tests := []struct {
		port string
		term string
		want bool
	}{
		{"443", "WEB-PORTS", true},
		{"https", "WEB-PORTS", true},
		{"80", "WEB-PORTS", true},
		{"8085", "WEB-PORTS", true},
		{"8080-8082", "WEB-PORTS", true},
		{"8090-8095", "WEB-PORTS", true}, // диапазон пересекается с разрешенным
		{"8443", "WEB-PORTS", false},
		{"22", "WEB-PORTS", false},
		{"22", "SINGLE-PORT", true},
		{"20-25", "SINGLE-PORT", true},
		{"23", "SINGLE-PORT", false},
		{"garbage", "SINGLE-PORT", false},
		{"70000", "SINGLE-PORT", false},
	}
	for _, tt := range tests {
		rules := allowedRules(t, "", "10.2.2.2", tt.port)
		if got := hasTerm(rules, tt.term); got != tt.want {
			t.Errorf("port %q: term %s matched = %v, want %v", tt.port, tt.term, got, tt.want)
		}
	}
}

// Имена термов через запятую
func termNames(rules []GroupedRule) string {
	var names []string
	for _, rule := range rules {
		names = append(names, rule.TermName)
	}
	return strings.Join(names, ",")
}

func findRule(t *testing.T, rules []GroupedRule, name string) GroupedRule {
	t.Helper()
	for _, rule := range rules {
		if rule.TermName == name {
			return rule
		}
	}
	t.Fatalf("term %q not found in %q", name, termNames(rules))
	return GroupedRule{}
}

const orderTestConf = `filter EDGE-IN {
    term COUNT-ALL {
        then {
            count all;
            next term;
        }
    }
    term DENY-BAD-HOST {
        from {
            source-address {
                10.1.1.66/32;
            }
        }
        then discard;
    }
    term DENY-DB-TELNET {
        from {
            destination-prefix-list {
                DB;
            }
            protocol tcp;
            destination-port telnet;
        }
        then reject;
    }
    term DENY-UDP-TO-DB {
        from {
            destination-prefix-list {
                DB;
            }
            protocol udp;
        }
        then discard;
    }
    term DENY-OTHER-NET {
        from {
            destination-address {
                172.16.0.0/12;
            }
        }
        then discard;
    }
    term ALLOW-WEB-TO-DB {
        from {
            source-prefix-list {
                WEB;
            }
            destination-prefix-list {
                DB;
            }
            protocol tcp;
        }
        then accept;
    }
    term ALLOW-WEB-ANY {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then accept;
    }
    term DENY-REST {
        then discard;
    }
    term ALLOW-AFTER-DENY {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then accept;
    }
}
`

func TestFirstMatchOrder(t *testing.T) {
	loadTestConfig(t, testACL, orderTestConf)

	t.Run("deny term above blocks the host", func(t *testing.T) {
		result := checkAccess(getState(), mustQuery(t, "10.1.1.66", "10.2.2.2", "443"), "")
		if len(result.Allowed) != 0 {
			t.Errorf("allowed = %q, want none", termNames(result.Allowed))
		}
		if got := termNames(result.Blocked); got != "DENY-BAD-HOST" {
			t.Errorf("blocked = %q, want DENY-BAD-HOST", got)
		}
	})

	t.Run("accept term stops evaluation", func(t *testing.T) {
		// ALLOW-WEB-TO-DB покрывает запрос частично (protocol), ALLOW-WEB-ANY целиком.
		// До DENY-REST и ALLOW-AFTER-DENY трафик не доходит
		result := checkAccess(getState(), mustQuery(t, "10.1.1.5", "10.2.2.2", "443"), "")
		if got := termNames(result.Allowed); got != "ALLOW-WEB-ANY,ALLOW-WEB-TO-DB" {
			t.Errorf("allowed = %q", got)
		}
		if len(result.Blocked) != 0 {
			t.Errorf("blocked = %q, want none", termNames(result.Blocked))
		}
	})

	t.Run("deny on another protocol is reported only for overlapping terms", func(t *testing.T) {
		result := checkAccess(getState(), mustQuery(t, "10.1.1.5", "10.2.2.2", "443"), "")

		// tcp-терм не пересекается с запретом udp
		if rule := findRule(t, result.Allowed, "ALLOW-WEB-TO-DB"); len(rule.ShadowedBy) != 0 {
			t.Errorf("ALLOW-WEB-TO-DB shadowed by %v", rule.ShadowedBy)
		}
		// терм без протокола может потерять udp
		rule := findRule(t, result.Allowed, "ALLOW-WEB-ANY")
		if got := strings.Join(rule.ShadowedBy, ","); got != "DENY-UDP-TO-DB" {
			t.Errorf("ALLOW-WEB-ANY shadowed by %q, want DENY-UDP-TO-DB", got)
		}
	})

	t.Run("partial deny on the queried port", func(t *testing.T) {
		result := checkAccess(getState(), mustQuery(t, "10.1.1.5", "10.2.2.2", "23"), "")
		rule := findRule(t, result.Allowed, "ALLOW-WEB-TO-DB")
		if got := strings.Join(rule.ShadowedBy, ","); got != "DENY-DB-TELNET" {
			t.Errorf("shadowed by %q, want DENY-DB-TELNET", got)
		}
	})

	t.Run("unrelated destination deny is not reported", func(t *testing.T) {
		result := checkAccess(getState(), mustQuery(t, "10.1.1.5", "", ""), "")
		rule := findRule(t, result.Allowed, "ALLOW-WEB-TO-DB")
		if containsString(rule.ShadowedBy, "DENY-OTHER-NET") {
			t.Errorf("shadowed by %v", rule.ShadowedBy)
		}
		// а терм без условия по destination этот запрет задевает
		rule = findRule(t, result.Allowed, "ALLOW-WEB-ANY")
		if !containsString(rule.ShadowedBy, "DENY-OTHER-NET") {
			t.Errorf("ALLOW-WEB-ANY shadowed by %v, want DENY-OTHER-NET included", rule.ShadowedBy)
		}
	})

	t.Run("implicit and explicit deny for unknown source", func(t *testing.T) {
		result := checkAccess(getState(), mustQuery(t, "8.8.8.8", "10.2.2.2", "443"), "")
		if len(result.Allowed) != 0 {
			t.Errorf("allowed = %q, want none", termNames(result.Allowed))
		}
		if got := termNames(result.Blocked); got != "DENY-REST" {
			t.Errorf("blocked = %q, want DENY-REST", got)
		}
	})
}

func TestFiltersAreEvaluatedSeparately(t *testing.T) {
	denyThenAllow := `filter SHARED {
    term STOP {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then discard;
    }
    term PASS {
        then accept;
    }
}
`
	allowOnly := `filter SHARED {
    term PASS {
        then accept;
    }
}
filter OTHER {
    term LOCAL {
        from {
            source-address {
                10.1.1.5/32;
            }
        }
        then accept;
    }
}
`
	loadTestFiles(t, map[string]string{
		"jcore1.acl.txt":      testACL,
		"jcore1.acl.conf.txt": denyThenAllow,
		"jcore2.acl.conf.txt": allowOnly,
	})

	// Одноименный фильтр на другом устройстве не наследует запрет с первого
	result := checkAccess(getState(), mustQuery(t, "10.1.1.5", "", ""), "")
	if got := termNames(result.Allowed); got != "LOCAL,PASS" {
		t.Errorf("allowed = %q, want LOCAL,PASS", got)
	}

	result = checkAccess(getState(), mustQuery(t, "10.1.1.5", "", ""), "OTHER")
	if got := termNames(result.Allowed); got != "LOCAL" {
		t.Errorf("filter OTHER: allowed = %q, want LOCAL", got)
	}

	result = checkAccess(getState(), mustQuery(t, "10.1.1.5", "", ""), "NO-SUCH-FILTER")
	if len(result.Allowed) != 0 || len(result.Blocked) != 0 {
		t.Errorf("unknown filter returned rules: %+v", result)
	}
}

func TestGroupingKeepsDifferentTermsApart(t *testing.T) {
	loadTestConfig(t, testACL, `filter A {
    term SAME-NAME {
        from {
            source-address {
                10.1.1.0/24;
            }
        }
        then accept;
    }
    term IDENTICAL {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then accept;
    }
}
filter B {
    term SAME-NAME {
        from {
            source-address {
                10.9.9.0/24;
            }
        }
        then accept;
    }
    term IDENTICAL {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then accept;
    }
}
`)

	rules := searchRulesWithGrouping(getState(), "SAME-NAME")
	if len(rules) != 2 {
		t.Fatalf("got %d cards for SAME-NAME, want 2", len(rules))
	}
	for _, rule := range rules {
		if len(rule.SourcePrefixes) != 1 || len(rule.Filters) != 1 {
			t.Errorf("card mixes filters: prefixes=%v filters=%v", rule.SourcePrefixes, rule.Filters)
		}
	}

	rules = searchRulesWithGrouping(getState(), "IDENTICAL")
	if len(rules) != 1 || strings.Join(rules[0].Filters, ",") != "A,B" {
		t.Errorf("identical terms must be grouped: %+v", rules)
	}
}

func TestCheckPage(t *testing.T) {
	loadTestConfig(t, testACL, orderTestConf)

	tests := []struct {
		target string
		status int
		want   []string
		absent []string
	}{
		{
			target: "/check?src=10.1.1.5&dst=10.2.2.2&port=443&filter=EDGE-IN",
			status: http.StatusOK,
			want: []string{
				"ACCESS OPEN",
				"Term: ALLOW-WEB-TO-DB",
				`<option value="EDGE-IN" selected>`,
				"<strong>Filter:</strong> EDGE-IN",
			},
			absent: []string{"ACCESS DENIED", "PARTIALLY"},
		},
		{
			target: "/check?src=10.1.1.66&dst=10.2.2.2",
			status: http.StatusOK,
			want:   []string{"ACCESS DENIED", "Term: DENY-BAD-HOST", "✗ Discard"},
			absent: []string{"ACCESS OPEN"},
		},
		{
			target: "/check?src=8.8.8.8&filter=NO-SUCH-FILTER",
			status: http.StatusOK,
			want:   []string{"ACCESS DENIED", "No matching rules were found"},
		},
		{
			target: "/check?src=10.1.1.5&dst=10.2.2.2&port=99999",
			status: http.StatusBadRequest,
			want:   []string{"INVALID REQUEST", "invalid port or port range"},
			absent: []string{"ACCESS OPEN", "ACCESS DENIED"},
		},
		{
			target: "/check?src=10.1.1.300",
			status: http.StatusBadRequest,
			want:   []string{"invalid source address or network"},
		},
	}
	for _, tt := range tests {
		rec := get(t, tt.target)
		body := rec.Body.String()
		if rec.Code != tt.status {
			t.Errorf("%s: status %d, want %d", tt.target, rec.Code, tt.status)
		}
		for _, want := range tt.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s: %q not found", tt.target, want)
			}
		}
		for _, absent := range tt.absent {
			if strings.Contains(body, absent) {
				t.Errorf("%s: unexpected %q", tt.target, absent)
			}
		}
	}
}

func TestCheckPagePartialAccess(t *testing.T) {
	loadTestConfig(t, testACL, `filter EDGE-IN {
    term DENY-DB-TELNET {
        from {
            destination-prefix-list {
                DB;
            }
            destination-port telnet;
        }
        then discard;
    }
    term ALLOW-WEB {
        from {
            source-prefix-list {
                WEB;
            }
        }
        then accept;
    }
}
`)

	body := get(t, "/check?src=10.1.1.5&dst=10.2.2.2").Body.String()
	for _, want := range []string{"ACCESS PARTIALLY OPEN", "May be blocked earlier in the filter by", "DENY-DB-TELNET"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q not found", want)
		}
	}

	// Для конкретного порта запрет либо срабатывает целиком, либо не мешает
	if body := get(t, "/check?src=10.1.1.5&dst=10.2.2.2&port=23").Body.String(); !strings.Contains(body, "ACCESS DENIED") {
		t.Error("telnet must be denied")
	}
	if body := get(t, "/check?src=10.1.1.5&dst=10.2.2.2&port=443").Body.String(); !strings.Contains(body, "ACCESS OPEN") {
		t.Error("https must be open")
	}
}

func TestStaticFiles(t *testing.T) {
	files := map[string]string{
		"/static/snow-init.js":                   "text/javascript",
		"/static/check.js":                       "text/javascript",
		"/static/vendor/snowflakes/Snow.min.js":  "text/javascript",
		"/static/vendor/snowflakes/snow.min.css": "text/css",
	}
	for target, contentType := range files {
		rec := get(t, target)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", target, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, contentType) {
			t.Errorf("%s: Content-Type %q, want %s", target, got, contentType)
		}
	}

	for _, target := range []string{"/static/", "/static/vendor/", "/static/nope.js", "/static/../main.go"} {
		if rec := get(t, target); rec.Code == http.StatusOK {
			t.Errorf("%s: must not be served", target)
		}
	}
}

// CSP разрешает скрипты только из своих файлов, поэтому в страницах не должно быть
// ни inline-скриптов, ни обработчиков в атрибутах, ни сторонних ресурсов
func TestPagesFollowCSP(t *testing.T) {
	loadTestConfig(t, testACL, orderTestConf)

	scriptTag := regexp.MustCompile(`(?i)<script\b[^>]*>`)
	scriptSrc := regexp.MustCompile(`(?i)\bsrc="/static/[^"]+"`)
	inlineHandler := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	resource := regexp.MustCompile(`(?i)<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)="(?:https?:)?//`)

	for _, target := range []string{"/", "/search?q=WEB", "/search?q=nothing", "/check", "/check?src=10.1.1.5&dst=10.2.2.2"} {
		body := get(t, target).Body.String()

		for _, tag := range scriptTag.FindAllString(body, -1) {
			if !scriptSrc.MatchString(tag) {
				t.Errorf("%s: script not loaded from /static/: %s", target, tag)
			}
		}
		if inlineHandler.MatchString(body) {
			t.Errorf("%s: inline event handler found", target)
		}
		if match := resource.FindString(body); match != "" {
			t.Errorf("%s: third-party resource: %s", target, match)
		}
	}
}

func TestRouting(t *testing.T) {
	loadTestConfig(t, testACL, "filter F {\n    term T1 {\n        then accept;\n    }\n}\n")

	if rec := get(t, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("/nope: status %d, want 404", rec.Code)
	}
	if rec := get(t, "/search"); rec.Code != http.StatusSeeOther {
		t.Errorf("/search without query: status %d, want redirect", rec.Code)
	}

	for _, target := range []string{"/", "/check", "/search?q=x", "/api/memory"} {
		rec := httptest.NewRecorder()
		newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: status %d, want 405", target, rec.Code)
		}
	}
}

func TestJiraLinkIgnoresCase(t *testing.T) {
	loadTestConfig(t, testACL, "filter F {\n    term NOC-7 {\n        then accept;\n    }\n}\n")
	t.Setenv("JIRA_URL", "https://jira.example.com/browse/")

	body := get(t, "/search?q=noc-7").Body.String()
	if !strings.Contains(body, `href="https://jira.example.com/browse/NOC-7"`) {
		t.Errorf("lowercase task id must link to Jira:\n%s", linkLines(body))
	}
	if !strings.Contains(body, "Term: NOC-7") {
		t.Error("term not found by lowercase task id")
	}
}

func TestProbes(t *testing.T) {
	// Данных нет: процесс жив, но к работе не готов
	currentState.Store(newAppState())
	if rec := get(t, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz without data: status %d, want 200", rec.Code)
	}
	if rec := get(t, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz without data: status %d, want 503", rec.Code)
	}

	loadTestConfig(t, testACL, "filter F {\n    term T1 {\n        then accept;\n    }\n}\n")
	for _, target := range []string{"/healthz", "/readyz"} {
		rec := get(t, target)
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
			t.Errorf("%s: status %d, body %q", target, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q", target, got)
		}
	}

	// Неудачная перезагрузка оставляет прежние данные, сервис остается готовым
	if err := os.RemoveAll("jcore-filters"); err != nil {
		t.Fatal(err)
	}
	_ = loadConfigFiles()
	if rec := get(t, "/readyz"); rec.Code != http.StatusOK {
		t.Errorf("/readyz after a failed reload: status %d, want 200", rec.Code)
	}

	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz: status %d, want 405", rec.Code)
	}
}
