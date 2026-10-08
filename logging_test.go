package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// По умолчанию тесты логи не печатают, проверяющие логи тесты перехватывают их сами
func TestMain(m *testing.M) {
	initLogging(io.Discard)
	os.Exit(m.Run())
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// Перехватывает логи на время теста
func captureLogs(t *testing.T, level slog.Level) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	previous := logLevel.Level()

	logLevel.Set(level)
	initLogging(out)
	t.Cleanup(func() {
		logLevel.Set(previous)
		initLogging(io.Discard)
	})
	return out
}

// Разбирает перехваченный вывод: каждая непустая строка должна быть JSON-объектом
func logLines(t *testing.T, out *syncBuffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if raw == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("log line is not JSON: %v\n%s", err, raw)
		}
		line["_raw"] = raw
		lines = append(lines, line)
	}
	return lines
}

// Строки, в msg которых есть подстрока
func linesWithMsg(lines []map[string]any, substr string) []map[string]any {
	var found []map[string]any
	for _, line := range lines {
		if msg, _ := line["msg"].(string); strings.Contains(msg, substr) {
			found = append(found, line)
		}
	}
	return found
}

var (
	logTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	ipv4Pattern    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	fieldPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Имена, которые сборщик перезаписывает или удаляет
var reservedLogFields = []string{
	"service", "hostname", "env", "namespace", "timestamp", "time_local",
	"time_iso8601", "level_name", "kubernetes", "stream", "file", "source_type",
}

// Проверяет строку на соответствие правилам логирования
func checkLogLine(t *testing.T, line map[string]any) {
	t.Helper()
	raw := line["_raw"].(string)

	timeValue, _ := line["time"].(string)
	if !logTimePattern.MatchString(timeValue) {
		t.Errorf("time %q is not RFC3339 UTC: %s", timeValue, raw)
	} else if _, err := time.Parse(time.RFC3339Nano, timeValue); err != nil {
		t.Errorf("time %q does not parse: %v", timeValue, err)
	}

	switch level, _ := line["level"].(string); level {
	case "debug", "info", "warn", "error":
	default:
		t.Errorf("level %q is not allowed: %s", level, raw)
	}

	msg, _ := line["msg"].(string)
	if strings.TrimSpace(msg) == "" {
		t.Errorf("empty msg: %s", raw)
	}
	// Первый IPv4 из msg сборщик записывает в remote_addr
	if ipv4Pattern.MatchString(msg) {
		t.Errorf("msg contains an IPv4 address: %s", raw)
	}
	if strings.Contains(raw, "kube-probe") {
		t.Errorf("line contains a substring dropped by the collector: %s", raw)
	}

	if line["app"] != appName {
		t.Errorf("app = %v: %s", line["app"], raw)
	}
	if component, _ := line["component"].(string); component == "" {
		t.Errorf("component is missing: %s", raw)
	}

	fields := 0
	for name, value := range line {
		if name == "_raw" {
			continue
		}
		if !fieldPattern.MatchString(name) {
			t.Errorf("field %q is not snake_case: %s", name, raw)
		}
		for _, reserved := range reservedLogFields {
			if name == reserved {
				t.Errorf("field %q is reserved by the collector: %s", name, raw)
			}
		}
		switch value.(type) {
		case map[string]any, []any:
			t.Errorf("field %q is nested, keep the structure flat: %s", name, raw)
		}
		if name != "time" && name != "level" && name != "msg" {
			fields++
		}
	}
	if fields > 15 {
		t.Errorf("%d own fields, the guideline is up to 15: %s", fields, raw)
	}
	if len(raw) > 16*1024 {
		t.Errorf("line is %d bytes, the limit is about 16 KB", len(raw))
	}
}

const logTestConf = `filter EDGE-IN {
    term DENY-BAD-HOST {
        from {
            source-address {
                10.1.1.66/32;
            }
        }
        then discard;
    }
    term ALLOW-WEB {
        from {
            source-prefix-list {
                WEB;
            }
            destination-prefix-list {
                DB;
            }
            destination-port [ https strange-port ];
        }
        then accept;
    }
    term ODD-MASK {
        from {
            source-address {
                100.100.1.0/255.252.255.0;
            }
            source-prefix-list {
                NO-SUCH-LIST;
            }
        }
        then accept;
    }
}
`

func TestAllLogLinesFollowGuidelines(t *testing.T) {
	out := captureLogs(t, slog.LevelDebug)
	loadTestConfig(t, testACL, logTestConf)

	// Повторная загрузка, загрузка с ошибкой и без данных
	if err := loadConfigFiles(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join("jcore-filters", "jcore9.acl.conf.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = loadConfigFiles()
	if err := os.RemoveAll("jcore-filters"); err != nil {
		t.Fatal(err)
	}
	_ = loadConfigFiles()

	targets := []string{
		"/",
		"/check",
		"/check?src=10.1.1.5&dst=10.2.2.2&port=443&filter=EDGE-IN",
		"/check?src=10.1.1.66",
		"/check?src=999.1.1.1",
		"/search?q=10.1.1.0/24",
		"/search?q=" + strings.Repeat("10.9.9.9-", 5000),
		"/search",
		"/10.20.30.40/secret",
		"/static/script.js",
		"/static/10.1.1.1.js",
		"/api/memory",
	}
	for _, target := range targets {
		get(t, target)
	}

	// Сообщения стандартного пакета log тоже должны выходить в JSON
	log.Print("message from the standard log package")
	slog.NewLogLogger(componentLogger("http").Handler(), slog.LevelError).Print("http: internal error")

	lines := logLines(t, out)
	if len(lines) < len(targets) {
		t.Fatalf("only %d log lines captured", len(lines))
	}
	for _, line := range lines {
		checkLogLine(t, line)
	}

	for _, want := range []string{"filters loaded", "filters unchanged", "cannot read filter file", "keeping previous state", "no filter data loaded", "http: internal error"} {
		if len(linesWithMsg(lines, want)) == 0 {
			t.Errorf("no log line with %q", want)
		}
	}
}

func TestAccessLogFields(t *testing.T) {
	loadTestConfig(t, testACL, logTestConf)
	out := captureLogs(t, slog.LevelInfo)

	get(t, "/check?src=10.1.1.5&dst=10.2.2.2&port=443&filter=EDGE-IN")
	get(t, "/search?q=WEB")
	get(t, "/check?src=10.1.1.66&dst=10.2.2.2")
	get(t, "/check?port=abc")
	get(t, "/no/such/page")

	lines := logLines(t, out)
	if len(lines) != 5 {
		t.Fatalf("got %d access log lines, want 5:\n%s", len(lines), out.String())
	}

	want := []map[string]any{
		{"level": "info", "msg": "GET /check -> 200", "path": "/check", "status": 200.0, "src": "10.1.1.5", "dst": "10.2.2.2", "port": "443", "filter": "EDGE-IN", "result": "open", "matches": 1.0},
		{"level": "info", "msg": "GET /search -> 200", "path": "/search", "status": 200.0, "query": "WEB", "matches": 1.0},
		{"level": "info", "msg": "GET /check -> 200", "status": 200.0, "src": "10.1.1.66", "result": "denied", "matches": 0.0},
		{"level": "warn", "msg": "GET /check -> 400", "status": 400.0, "port": "abc", "result": "invalid"},
		{"level": "warn", "msg": "GET (no route) -> 404", "path": "/no/such/page", "status": 404.0},
	}
	for i, fields := range want {
		line := lines[i]
		for name, value := range fields {
			if name == "msg" {
				if msg, _ := line["msg"].(string); !strings.HasPrefix(msg, value.(string)) {
					t.Errorf("line %d: msg = %q, want prefix %q", i, msg, value)
				}
				continue
			}
			if line[name] != value {
				t.Errorf("line %d: %s = %v, want %v", i, name, line[name], value)
			}
		}
		for _, name := range []string{"request_id", "remote_addr", "method", "duration_ms", "component"} {
			if _, ok := line[name]; !ok {
				t.Errorf("line %d: field %s is missing", i, name)
			}
		}
	}

	// Пустые параметры в лог не попадают
	if _, ok := lines[2]["port"]; ok {
		t.Error("empty port must not be logged")
	}
}

func TestQuietRequestsAreNotLogged(t *testing.T) {
	loadTestConfig(t, testACL, logTestConf)
	out := captureLogs(t, slog.LevelInfo)

	get(t, "/static/script.js")
	get(t, "/static/styles.css")

	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.Header.Set("User-Agent", "kube-probe/1.31")
	newHandler().ServeHTTP(httptest.NewRecorder(), probe)

	if lines := logLines(t, out); len(lines) != 0 {
		t.Fatalf("quiet requests were logged:\n%s", out.String())
	}

	get(t, "/healthz")
	get(t, "/readyz")
	if lines := logLines(t, out); len(lines) != 0 {
		t.Fatalf("successful probes were logged:\n%s", out.String())
	}

	// Ошибки пишутся и для них
	get(t, "/static/missing.js")
	currentState.Store(newAppState())
	get(t, "/readyz")

	lines := logLines(t, out)
	if len(lines) != 2 {
		t.Fatalf("got %d lines for failed quiet requests, want 2:\n%s", len(lines), out.String())
	}
	if lines[0]["status"] != 404.0 || lines[0]["level"] != "warn" {
		t.Errorf("unexpected line: %s", lines[0]["_raw"])
	}
	if lines[1]["status"] != 503.0 || lines[1]["level"] != "error" || lines[1]["path"] != "/readyz" {
		t.Errorf("unexpected line: %s", lines[1]["_raw"])
	}
	for _, line := range lines {
		checkLogLine(t, line)
		if _, ok := line["response_bytes"]; ok {
			t.Errorf("response_bytes must not be logged: %s", line["_raw"])
		}
	}
}

func TestRequestID(t *testing.T) {
	loadTestConfig(t, testACL, logTestConf)
	out := captureLogs(t, slog.LevelInfo)

	tests := []struct {
		header string
		keep   bool
	}{
		{"a57715016152c37941cc769df82ecec9", true},
		{"req-2026.10_08", true},
		{"", false},
		{"has space", false},
		{`"><script>`, false},
		{strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		out.Reset()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tt.header != "" {
			req.Header.Set("X-Request-Id", tt.header)
		}
		rec := httptest.NewRecorder()
		newHandler().ServeHTTP(rec, req)

		lines := logLines(t, out)
		if len(lines) != 1 {
			t.Fatalf("header %q: %d log lines", tt.header, len(lines))
		}
		logged, _ := lines[0]["request_id"].(string)
		returned := rec.Header().Get("X-Request-Id")

		if logged == "" || logged != returned {
			t.Errorf("header %q: logged %q, returned %q", tt.header, logged, returned)
		}
		if tt.keep && logged != tt.header {
			t.Errorf("header %q: replaced by %q", tt.header, logged)
		}
		if !tt.keep && (logged == tt.header || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(logged)) {
			t.Errorf("header %q: expected a generated id, got %q", tt.header, logged)
		}
	}
}

func TestClientAddr(t *testing.T) {
	proxies, err := parseTrustedProxies("10.42.0.0/16, 192.168.0.1")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		trusted   bool
		remote    string
		forwarded []string
		want      string
	}{
		{"no proxies configured, header ignored", false, "10.42.0.7:5000", []string{"203.0.113.9"}, "10.42.0.7"},
		{"untrusted peer, header ignored", true, "198.51.100.4:5000", []string{"203.0.113.9"}, "198.51.100.4"},
		{"trusted peer", true, "10.42.0.7:5000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"trusted peer, chain of proxies", true, "10.42.0.7:5000", []string{"203.0.113.9, 192.168.0.1, 10.42.3.3"}, "203.0.113.9"},
		{"spoofed leftmost value", true, "10.42.0.7:5000", []string{"1.1.1.1, 203.0.113.9"}, "203.0.113.9"},
		{"several header lines", true, "10.42.0.7:5000", []string{"1.1.1.1", "203.0.113.9"}, "203.0.113.9"},
		{"trusted peer without header", true, "10.42.0.7:5000", nil, "10.42.0.7"},
		{"garbage in header", true, "10.42.0.7:5000", []string{"not-an-ip"}, "10.42.0.7"},
		{"only proxies in header", true, "10.42.0.7:5000", []string{"10.42.1.1"}, "10.42.0.7"},
		{"ipv6 client", true, "10.42.0.7:5000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"ipv6 peer", false, "[2001:db8::7]:5000", nil, "2001:db8::7"},
	}
	for _, tt := range tests {
		trustedProxies = nil
		if tt.trusted {
			trustedProxies = proxies
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tt.remote
		for _, value := range tt.forwarded {
			req.Header.Add("X-Forwarded-For", value)
		}
		if got := clientAddr(req); got != tt.want {
			t.Errorf("%s: clientAddr = %q, want %q", tt.name, got, tt.want)
		}
	}
	trustedProxies = nil

	for _, bad := range []string{"10.0.0.0/33", "proxy.local", "10.1.1.1;10.2.2.2"} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Errorf("parseTrustedProxies(%q) must fail", bad)
		}
	}
	if proxies, err := parseTrustedProxies(" , "); err != nil || len(proxies) != 0 {
		t.Errorf("empty list: %v, %v", proxies, err)
	}
}

func TestPanicIsLoggedAsOneLine(t *testing.T) {
	out := captureLogs(t, slog.LevelInfo)

	handler := logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rules []PolicyRule
		_ = rules[3] // выход за границы
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", rec.Code)
	}

	lines := logLines(t, out)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want panic and access lines:\n%s", len(lines), out.String())
	}
	for _, line := range lines {
		checkLogLine(t, line)
		if line["level"] != "error" {
			t.Errorf("level = %v, want error", line["level"])
		}
	}

	panicLine := lines[0]
	if msg, _ := panicLine["msg"].(string); !strings.HasPrefix(msg, "panic while handling") {
		t.Errorf("msg = %q", msg)
	}
	if text, _ := panicLine["error"].(string); !strings.Contains(text, "index out of range") {
		t.Errorf("error = %q", text)
	}
	stack, _ := panicLine["stacktrace"].(string)
	if !strings.Contains(stack, "logging_test.go") || !strings.Contains(stack, "\n") {
		t.Errorf("stacktrace does not point to the failing code: %q", stack)
	}
	if panicLine["request_id"] != lines[1]["request_id"] || lines[1]["status"] != 500.0 {
		t.Errorf("panic and access lines are not linked: %s", out.String())
	}
}

func TestReloadPanicIsLogged(t *testing.T) {
	out := captureLogs(t, slog.LevelInfo)
	t.Chdir(t.TempDir())

	// nil вместо состояния роняет загрузчик
	previous := currentState.Load()
	currentState.Store(nil)
	t.Cleanup(func() { currentState.Store(previous) })

	reloadSafely()

	lines := linesWithMsg(logLines(t, out), "panic while reloading filters")
	if len(lines) != 1 {
		t.Fatalf("panic is not logged:\n%s", out.String())
	}
	checkLogLine(t, lines[0])
	if stack, _ := lines[0]["stacktrace"].(string); !strings.Contains(stack, "loadConfigFiles") {
		t.Errorf("stacktrace = %q", stack)
	}
}

func TestReloadLogsOnlyChanges(t *testing.T) {
	out := captureLogs(t, slog.LevelInfo)
	loadTestConfig(t, testACL, logTestConf)

	lines := logLines(t, out)
	loaded := linesWithMsg(lines, "filters loaded: 2 prefix lists, 3 rules from 2 files")
	if len(loaded) != 1 {
		t.Fatalf("first load is not reported:\n%s", out.String())
	}
	if loaded[0]["prefix_lists"] != 2.0 || loaded[0]["rules"] != 3.0 || loaded[0]["files"] != 2.0 {
		t.Errorf("unexpected fields: %s", loaded[0]["_raw"])
	}

	// Все три вида проблем названы один раз, значения лежат в полях
	problems := map[string]string{
		"missing_prefix_list": "NO-SUCH-LIST",
		"invalid_prefix":      "100.100.1.0/255.252.255.0",
		"invalid_port":        "strange-port",
	}
	for problem, sample := range problems {
		found := 0
		for _, line := range lines {
			if line["problem"] == problem {
				found++
				if line["level"] != "warn" || line["count"] != 1.0 || line["sample"] != sample {
					t.Errorf("unexpected warning: %s", line["_raw"])
				}
			}
		}
		if found != 1 {
			t.Errorf("problem %s reported %d times, want 1", problem, found)
		}
	}

	// Повторные загрузки без изменений на уровне info молчат
	out.Reset()
	for i := 0; i < 3; i++ {
		if err := loadConfigFiles(); err != nil {
			t.Fatal(err)
		}
	}
	if got := out.String(); got != "" {
		t.Errorf("unchanged reloads were logged:\n%s", got)
	}

	// Изменение данных сообщается, прежние проблемы не повторяются, исправленная закрывается
	fixed := strings.Replace(logTestConf, "NO-SUCH-LIST", "WEB", 1)
	if err := os.WriteFile(filepath.Join("jcore-filters", "jcore1.acl.conf.txt"), []byte(fixed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFiles(); err != nil {
		t.Fatal(err)
	}

	lines = logLines(t, out)
	if len(linesWithMsg(lines, "filters loaded")) != 1 {
		t.Errorf("changed data is not reported:\n%s", out.String())
	}
	if len(linesWithMsg(lines, "all referenced prefix lists are defined again")) != 1 {
		t.Errorf("resolved problem is not reported:\n%s", out.String())
	}
	if len(lines) != 2 {
		t.Errorf("got %d lines after a change, want 2:\n%s", len(lines), out.String())
	}
}

func TestLongProblemListsAreTruncated(t *testing.T) {
	out := captureLogs(t, slog.LevelInfo)

	var conf strings.Builder
	conf.WriteString("filter F {\n")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&conf, "term T%d {\nfrom {\nsource-prefix-list {\nMISSING-LIST-WITH-A-LONG-NAME-%04d;\n}\n}\nthen accept;\n}\n", i, i)
	}
	conf.WriteString("}\n")
	loadTestConfig(t, testACL, conf.String())

	lines := linesWithMsg(logLines(t, out), "3000 prefix lists are referenced but not defined")
	if len(lines) != 1 {
		t.Fatalf("warning not found:\n%.2000s", out.String())
	}
	checkLogLine(t, lines[0])
	if sample, _ := lines[0]["sample"].(string); len(strings.Fields(sample)) != maxLogSampleLen {
		t.Errorf("sample has %d items, want %d", len(strings.Fields(sample)), maxLogSampleLen)
	}
}

func TestUserValuesAreTruncated(t *testing.T) {
	loadTestConfig(t, testACL, logTestConf)
	out := captureLogs(t, slog.LevelInfo)

	get(t, "/search?q="+strings.Repeat("я", 5000))

	lines := logLines(t, out)
	if len(lines) != 1 {
		t.Fatalf("got %d lines", len(lines))
	}
	checkLogLine(t, lines[0])
	query, _ := lines[0]["query"].(string)
	if len(query) > maxLogValueLen+3 || !strings.HasSuffix(query, "...") {
		t.Errorf("query is %d bytes and ends with %q", len(query), query[len(query)-6:])
	}
	if strings.ContainsRune(query, '�') {
		t.Error("truncation broke a multibyte character")
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
		ok   bool
	}{
		{"", slog.LevelInfo, true},
		{"info", slog.LevelInfo, true},
		{"DEBUG", slog.LevelDebug, true},
		{" warn ", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"verbose", slog.LevelInfo, false},
		{"400", slog.LevelInfo, false},
	}
	for _, tt := range tests {
		got, err := parseLogLevel(tt.in)
		if got != tt.want || (err == nil) != tt.ok {
			t.Errorf("parseLogLevel(%q) = %v, %v", tt.in, got, err)
		}
	}

	for level, name := range map[slog.Level]string{
		slog.LevelDebug: "debug", slog.LevelInfo: "info", slog.LevelWarn: "warn", slog.LevelError: "error",
		slog.LevelError + 4: "error", slog.LevelDebug - 4: "debug",
	} {
		if got := levelName(level); got != name {
			t.Errorf("levelName(%v) = %q, want %q", level, got, name)
		}
	}
}

func TestLogLevelFiltersDebug(t *testing.T) {
	out := captureLogs(t, slog.LevelWarn)
	loadTestConfig(t, testACL, logTestConf)
	get(t, "/")
	get(t, "/missing")

	for _, line := range logLines(t, out) {
		if level := line["level"]; level != "warn" && level != "error" {
			t.Errorf("line below the configured level: %s", line["_raw"])
		}
	}
	if len(linesWithMsg(logLines(t, out), "404")) != 1 {
		t.Errorf("warn line is missing:\n%s", out.String())
	}
}
