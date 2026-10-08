package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Пишет конфиги во временную директорию и загружает их так же, как приложение
func loadTestConfig(t *testing.T, acl, conf string) {
	t.Helper()

	dir := t.TempDir()
	filters := filepath.Join(dir, "jcore-filters")
	if err := os.Mkdir(filters, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filters, "jcore1.acl.txt"), []byte(acl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filters, "jcore1.acl.conf.txt"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(dir)
	currentState.Store(newAppState())
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

	if rules := checkAccess(getState(), "10.1.1.5", "", ""); len(rules) != 0 {
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

	rules := checkAccess(getState(), "8.8.8.8", "10.2.2.2", "")
	if hasTerm(rules, "MISSING-SRC") {
		t.Error("term with undefined source prefix-list matched an arbitrary source")
	}
	if !hasTerm(rules, "ANY-SRC") {
		t.Error("term without source conditions must match any source")
	}

	if rules := checkAccess(getState(), "10.1.1.5", "8.8.8.8", ""); hasTerm(rules, "MISSING-DST") {
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
		if rec.Code != http.StatusOK {
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
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
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
		if rules := checkAccess(state, "8.8.8.8", "", ""); len(rules) != 0 {
			t.Fatalf("reader saw %d unresolved rules during reload", len(rules))
		}
		if rules := checkAccess(state, "10.0.7.9", "", ""); len(rules) != 1 {
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
