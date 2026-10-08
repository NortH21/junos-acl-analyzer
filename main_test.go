package main

import (
	"os"
	"path/filepath"
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
	appState = AppState{PrefixLists: make(map[string][]string)}
	if err := loadConfigFiles(); err != nil {
		t.Fatalf("loadConfigFiles: %v", err)
	}
}

// Возвращает action терма по имени
func termAction(t *testing.T, name string) string {
	t.Helper()
	for _, rule := range appState.PolicyRules {
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
	if len(appState.PolicyRules) != len(want) {
		t.Fatalf("parsed %d terms, want %d", len(appState.PolicyRules), len(want))
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

	if rules := checkAccess("10.1.1.5", "", ""); len(rules) != 0 {
		t.Errorf("discard term reported as allowing access: %+v", rules)
	}
}
