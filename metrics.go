package main

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Метрики в текстовом формате Prometheus. Пишем формат сами, чтобы не тянуть
// внешние библиотеки: метрик немного, и все они простые счетчики и значения

const metricsPrefix = "junos_acl_analyzer_"

// Счетчики перезагрузки фильтров
var (
	reloadsChanged   atomic.Int64 // данные изменились и загружены
	reloadsUnchanged atomic.Int64 // файлы не менялись
	reloadsFailed    atomic.Int64 // ошибка, работаем на прежних данных
	lastReloadOK     atomic.Int64 // unix-время последней успешной проверки файлов
)

type requestKey struct {
	route string
	code  int
}

// Счетчики запросов. Ключи - шаблон маршрута и код ответа: их число ограничено
// маршрутами сервиса, произвольные пути клиента сюда не попадают
var requestStats = struct {
	sync.Mutex
	count    map[requestKey]int64
	duration map[string]time.Duration
}{
	count:    make(map[requestKey]int64),
	duration: make(map[string]time.Duration),
}

func recordRequest(route string, code int, duration time.Duration) {
	requestStats.Lock()
	defer requestStats.Unlock()
	requestStats.count[requestKey{route, code}]++
	requestStats.duration[route] += duration
}

// Экранирует значение метки
func labelValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}

type metricsWriter struct {
	w io.Writer
}

func (m metricsWriter) header(name, kind, help string) {
	fmt.Fprintf(m.w, "# HELP %s%s %s\n# TYPE %s%s %s\n", metricsPrefix, name, help, metricsPrefix, name, kind)
}

func (m metricsWriter) value(name, labels string, value float64) {
	if labels != "" {
		labels = "{" + labels + "}"
	}
	// Без экспоненты: время в секундах так читается и сравнивается проще
	fmt.Fprintf(m.w, "%s%s%s %s\n", metricsPrefix, name, labels, strconv.FormatFloat(value, 'f', -1, 64))
}

// Время как unix-секунды; для нулевого времени 0, чтобы алерт "данные устарели" сработал
func unixSeconds(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	state := getState()
	m := metricsWriter{w}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	m.header("prefix_lists", "gauge", "Number of loaded prefix lists.")
	m.value("prefix_lists", "", float64(len(state.PrefixLists)))

	m.header("rules", "gauge", "Number of loaded filter terms.")
	m.value("rules", "", float64(len(state.PolicyRules)))

	m.header("filter_files", "gauge", "Number of filter files in the loaded data.")
	m.value("filter_files", "", float64(state.files))

	m.header("unparsed_values", "gauge", "Values from the filter files that could not be parsed or resolved.")
	m.value("unparsed_values", `kind="missing_prefix_list"`, float64(len(state.problems.missingLists)))
	m.value("unparsed_values", `kind="invalid_prefix"`, float64(len(state.problems.invalidPrefixes)))
	m.value("unparsed_values", `kind="invalid_port"`, float64(len(state.problems.invalidPorts)))

	m.header("data_changed_timestamp_seconds", "gauge", "Unix time when changed filter data was last loaded, 0 if nothing is loaded.")
	m.value("data_changed_timestamp_seconds", "", unixSeconds(state.loadedAt))

	m.header("last_reload_success_timestamp_seconds", "gauge", "Unix time of the last successful check of the filter files, 0 if there was none.")
	m.value("last_reload_success_timestamp_seconds", "", float64(lastReloadOK.Load()))

	m.header("reloads_total", "counter", "Checks of the filter files by result.")
	m.value("reloads_total", `result="changed"`, float64(reloadsChanged.Load()))
	m.value("reloads_total", `result="unchanged"`, float64(reloadsUnchanged.Load()))
	m.value("reloads_total", `result="error"`, float64(reloadsFailed.Load()))

	requestStats.Lock()
	keys := make([]requestKey, 0, len(requestStats.count))
	for key := range requestStats.count {
		keys = append(keys, key)
	}
	counts := make(map[requestKey]int64, len(keys))
	for _, key := range keys {
		counts[key] = requestStats.count[key]
	}
	durations := make(map[string]time.Duration, len(requestStats.duration))
	for route, duration := range requestStats.duration {
		durations[route] = duration
	}
	requestStats.Unlock()

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		return keys[i].code < keys[j].code
	})

	m.header("http_requests_total", "counter", "HTTP requests by route and status code.")
	for _, key := range keys {
		m.value("http_requests_total", fmt.Sprintf(`route="%s",code="%d"`, labelValue(key.route), key.code), float64(counts[key]))
	}

	routes := make([]string, 0, len(durations))
	for route := range durations {
		routes = append(routes, route)
	}
	sort.Strings(routes)

	m.header("http_request_duration_seconds_total", "counter", "Total time spent handling HTTP requests by route.")
	for _, route := range routes {
		m.value("http_request_duration_seconds_total", fmt.Sprintf(`route="%s"`, labelValue(route)), durations[route].Seconds())
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	m.header("memory_heap_alloc_bytes", "gauge", "Bytes of allocated heap objects, including garbage not yet collected.")
	m.value("memory_heap_alloc_bytes", "", float64(mem.HeapAlloc))

	m.header("memory_sys_bytes", "gauge", "Bytes of memory obtained from the operating system.")
	m.value("memory_sys_bytes", "", float64(mem.Sys))

	m.header("gc_cycles_total", "counter", "Completed garbage collection cycles.")
	m.value("gc_cycles_total", "", float64(mem.NumGC))

	m.header("goroutines", "gauge", "Number of goroutines.")
	m.value("goroutines", "", float64(runtime.NumGoroutine()))

	m.header("start_timestamp_seconds", "gauge", "Unix time when the process started.")
	m.value("start_timestamp_seconds", "", unixSeconds(startTime))
}
