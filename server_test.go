package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Запускает serve на свободном локальном порту
func startTestServer(t *testing.T, handler http.Handler, grace time.Duration) (url string, stop context.CancelFunc, done chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done = make(chan error, 1)
	go func() { done <- serve(ctx, listener, handler, grace) }()
	return "http://" + listener.Addr().String(), cancel, done
}

func TestShutdownWaitsForRequests(t *testing.T) {
	out := captureLogs(t, slog.LevelInfo)

	started := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "done")
	})
	url, stop, done := startTestServer(t, handler, 5*time.Second)

	type result struct {
		body string
		err  error
	}
	response := make(chan result, 1)
	go func() {
		resp, err := http.Get(url)
		if err != nil {
			response <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		response <- result{string(body), err}
	}()

	// Запрос уже обрабатывается, когда приходит сигнал остановки
	<-started
	stop()

	select {
	case err := <-done:
		t.Fatalf("server stopped before the request finished: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	if got := <-response; got.err != nil || got.body != "done" {
		t.Errorf("in-flight request: body %q, error %v", got.body, got.err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}

	// Новые соединения больше не принимаются
	client := http.Client{Timeout: time.Second}
	if resp, err := client.Get(url); err == nil {
		resp.Body.Close()
		t.Error("server still accepts connections after shutdown")
	}

	lines := logLines(t, out)
	for _, line := range lines {
		checkLogLine(t, line)
	}
	if len(linesWithMsg(lines, "shutdown requested")) != 1 || len(linesWithMsg(lines, "server stopped")) != 1 {
		t.Errorf("shutdown is not logged:\n%s", out.String())
	}
}

func TestShutdownTimesOut(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	})
	url, stop, done := startTestServer(t, handler, 100*time.Millisecond)

	go func() {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	stop()

	select {
	case err := <-done:
		if err == nil {
			t.Error("serve must report that the shutdown timed out")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop after the grace period")
	}
}

func TestServeReportsListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()

	if err := serve(context.Background(), listener, http.NotFoundHandler(), time.Second); err == nil {
		t.Error("serve on a closed listener must fail")
	}
}

func TestReloadLoopStopsWithContext(t *testing.T) {
	loadTestConfig(t, testACL, logTestConf)
	before := reloadsUnchanged.Load()

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		autoReloadConfigs(ctx, 10*time.Millisecond)
		close(finished)
	}()

	// Цикл действительно перечитывает файлы
	deadline := time.Now().Add(5 * time.Second)
	for reloadsUnchanged.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("reload loop did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("reload loop did not stop")
	}
}

var metricLine = regexp.MustCompile(`^(junos_acl_analyzer_[a-z_]+)(\{[^{}]*\})? ([-+0-9.eE]+)$`)

// Разбирает вывод /metrics и проверяет формат: у каждой метрики есть HELP и TYPE
func parseMetrics(t *testing.T, body string) map[string]float64 {
	t.Helper()
	values := make(map[string]float64)
	described := make(map[string]bool)

	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if strings.HasPrefix(line, "# TYPE ") {
			described[strings.Fields(line)[2]] = true
			continue
		}
		if strings.HasPrefix(line, "# HELP ") {
			continue
		}
		match := metricLine.FindStringSubmatch(line)
		if match == nil {
			t.Errorf("malformed metric line: %q", line)
			continue
		}
		if !described[match[1]] {
			t.Errorf("metric %s has no TYPE line before its values", match[1])
		}
		value, err := strconv.ParseFloat(match[3], 64)
		if err != nil {
			t.Errorf("bad value in %q", line)
		}
		values[match[1]+match[2]] = value
	}
	return values
}

func TestMetrics(t *testing.T) {
	const p = "junos_acl_analyzer_"

	// Данных нет
	currentState.Store(newAppState())
	values := parseMetrics(t, get(t, "/metrics").Body.String())
	if values[p+"rules"] != 0 || values[p+"data_changed_timestamp_seconds"] != 0 {
		t.Errorf("metrics without data: rules=%v changed=%v", values[p+"rules"], values[p+"data_changed_timestamp_seconds"])
	}

	changedBefore := values[p+`reloads_total{result="changed"}`]
	failedBefore := values[p+`reloads_total{result="error"}`]
	checkBefore := values[p+`http_requests_total{route="GET /check",code="200"}`]

	loadTestConfig(t, testACL, logTestConf)
	_ = loadConfigFiles()
	get(t, "/check?src=10.1.1.5")
	get(t, "/check?src=10.1.1.5&dst=10.2.2.2")
	get(t, "/check?port=abc")
	get(t, "/10.20.30.40/secret-path")
	get(t, "/static/script.js")

	rec := get(t, "/metrics")
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type %q", got)
	}
	body := rec.Body.String()
	values = parseMetrics(t, body)

	want := map[string]float64{
		p + "prefix_lists": 2,
		p + "rules":        3,
		p + "filter_files": 2,
		p + `unparsed_values{kind="missing_prefix_list"}`:        1,
		p + `unparsed_values{kind="invalid_prefix"}`:             1,
		p + `unparsed_values{kind="invalid_port"}`:               1,
		p + `reloads_total{result="changed"}`:                    changedBefore + 1,
		p + `reloads_total{result="error"}`:                      failedBefore,
		p + `http_requests_total{route="GET /check",code="200"}`: checkBefore + 2,
	}
	for name, value := range want {
		if values[name] != value {
			t.Errorf("%s = %v, want %v", name, values[name], value)
		}
	}

	now := float64(time.Now().Unix())
	for _, name := range []string{"data_changed_timestamp_seconds", "last_reload_success_timestamp_seconds", "start_timestamp_seconds"} {
		if got := values[p+name]; got < now-3600 || got > now+1 {
			t.Errorf("%s = %v, expected a recent unix time", name, got)
		}
	}
	for _, name := range []string{
		`reloads_total{result="unchanged"}`,
		`http_requests_total{route="GET /check",code="400"}`,
		`http_requests_total{route="GET (no route)",code="404"}`,
		`http_requests_total{route="GET /static/",code="200"}`,
		`http_request_duration_seconds_total{route="GET /check"}`,
		`http_requests_total{route="GET /metrics",code="200"}`,
		"memory_heap_alloc_bytes", "memory_sys_bytes", "goroutines",
	} {
		if _, ok := values[p+name]; !ok {
			t.Errorf("metric %s is missing", name)
		}
	}

	// Пути и адреса, которые прислал клиент, в метки не попадают
	for _, leaked := range []string{"10.20.30.40", "secret-path", "10.1.1.5", "script.js"} {
		if strings.Contains(body, leaked) {
			t.Errorf("metrics expose client input %q", leaked)
		}
	}

	// Неудачная перезагрузка увеличивает счетчик ошибок
	t.Chdir(t.TempDir())
	_ = loadConfigFiles()
	values = parseMetrics(t, get(t, "/metrics").Body.String())
	if got := values[p+`reloads_total{result="error"}`]; got != failedBefore+1 {
		t.Errorf("reload errors = %v, want %v", got, failedBefore+1)
	}
}

func TestMetricsAreNotInAccessLog(t *testing.T) {
	loadTestConfig(t, testACL, logTestConf)
	out := captureLogs(t, slog.LevelInfo)

	get(t, "/metrics")
	if got := out.String(); got != "" {
		t.Errorf("metrics scrape was logged:\n%s", got)
	}
}

func TestLabelValueEscaping(t *testing.T) {
	if got := labelValue("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Errorf("labelValue = %q", got)
	}
}

func TestDataChangedOnPages(t *testing.T) {
	currentState.Store(newAppState())
	if body := get(t, "/").Body.String(); !strings.Contains(body, "Filters updated: not loaded") {
		t.Error("page without data must say that filters are not loaded")
	}

	loadTestConfig(t, testACL, logTestConf)
	loaded := getState().loadedAt
	if loaded.IsZero() || time.Since(loaded) > time.Minute {
		t.Fatalf("loadedAt = %v", loaded)
	}

	want := "Filters updated: " + loaded.Format("2006-01-02 15:04 MST")
	for _, target := range []string{"/", "/check", "/check?src=10.1.1.5", "/search?q=WEB", "/search?q=nothing"} {
		if body := get(t, target).Body.String(); !strings.Contains(body, want) {
			t.Errorf("%s: %q not found", target, want)
		}
	}

	// Перезагрузка без изменений время не сдвигает
	if err := loadConfigFiles(); err != nil {
		t.Fatal(err)
	}
	if !getState().loadedAt.Equal(loaded) {
		t.Error("unchanged reload moved the data timestamp")
	}
}
