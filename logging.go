package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

// Логи пишутся по одной JSON-строке на событие в stdout: обязательные поля
// time (RFC3339, UTC), level (строчными буквами) и msg, плюс app и component.
//
// В тексте msg не должно быть IPv4-адресов: сборщик берет первый найденный
// адрес и записывает его в remote_addr поверх настоящего. Адреса выносим в поля.

const appName = "junos-acl-analyzer"

// Формат времени: RFC3339 с миллисекундами, всегда UTC
const logTimeFormat = "2006-01-02T15:04:05.000Z"

// Ограничения, чтобы строка лога не превысила ~16 КБ
const (
	maxLogValueLen   = 256  // значение, пришедшее от пользователя
	maxLogSampleLen  = 10   // сколько элементов списка показывать
	maxStacktraceLen = 8192 // стектрейс
)

var (
	logLevel = new(slog.LevelVar)
	logger   *slog.Logger
)

func init() {
	initLogging(os.Stdout)
}

// Настраивает логгер приложения. Стандартный пакет log тоже направляется сюда,
// чтобы в выводе контейнера не появлялось строк мимо JSON
func initLogging(w io.Writer) {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       logLevel,
		ReplaceAttr: replaceLogAttr,
	})
	logger = slog.New(handler).With("app", appName)
	// Сюда попадает все, что пишут через стандартный log и slog по умолчанию
	slog.SetDefault(logger.With("component", "stdlog"))
}

// Приводит стандартные поля slog к принятому формату
func replaceLogAttr(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return attr
	}

	switch attr.Key {
	case slog.TimeKey:
		if t, ok := attr.Value.Any().(time.Time); ok {
			attr.Value = slog.StringValue(t.UTC().Format(logTimeFormat))
		}
	case slog.LevelKey:
		if level, ok := attr.Value.Any().(slog.Level); ok {
			attr.Value = slog.StringValue(levelName(level))
		}
	}
	return attr
}

// Имя уровня из списка, который понимает сборщик
func levelName(level slog.Level) string {
	switch {
	case level < slog.LevelInfo:
		return "debug"
	case level < slog.LevelWarn:
		return "info"
	case level < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

// Разбирает значение LOG_LEVEL
func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, fmt.Errorf("unknown log level %q, expected debug, info, warn or error", value)
}

// Логгер подсистемы: server, loader, http
func componentLogger(name string) *slog.Logger {
	return logger.With("component", name)
}

// Обрезает значение, пришедшее от пользователя
func truncateLogValue(value string) string {
	if len(value) <= maxLogValueLen {
		return value
	}
	return strings.ToValidUTF8(value[:maxLogValueLen], "") + "..."
}

// Первые элементы списка одной строкой. Массивы в хранилище логов ищутся плохо
func logSample(items []string) string {
	if len(items) > maxLogSampleLen {
		items = items[:maxLogSampleLen]
	}
	return strings.Join(items, " ")
}

// Сети прокси, от которых принимается X-Forwarded-For (переменная TRUSTED_PROXIES)
var trustedProxies []netip.Prefix

// Разбирает TRUSTED_PROXIES: адреса и сети через запятую
func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	var proxies []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, ok := parsePrefix(item)
		if !ok {
			return nil, fmt.Errorf("invalid address or network %q", item)
		}
		proxies = append(proxies, prefix)
	}
	return proxies, nil
}

func isTrustedProxy(addr netip.Addr) bool {
	for _, proxy := range trustedProxies {
		if proxy.Contains(addr) {
			return true
		}
	}
	return false
}

// Определяет адрес клиента. X-Forwarded-For учитывается, только если соединение
// пришло от доверенного прокси, иначе заголовок мог подставить сам клиент
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !isTrustedProxy(peer) {
		return peer.String()
	}

	// Идем справа налево: последний адрес добавил ближайший к нам прокси.
	// Клиент - первый адрес, который не принадлежит доверенным прокси
	var hops []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(header, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if !isTrustedProxy(addr) {
			return addr.String()
		}
	}
	return peer.String()
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Берет идентификатор запроса из заголовка, если он выглядит безопасно, иначе создает новый
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); requestIDPattern.MatchString(id) {
		return id
	}

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(raw[:])
}

// Поля, которые обработчик добавляет к строке access-лога своего запроса
type requestLog struct {
	attrs []slog.Attr
}

type requestLogKey struct{}

// Добавляет поля в access-лог текущего запроса: что искали, чем закончилась проверка
func addLogAttrs(r *http.Request, attrs ...slog.Attr) {
	if entry, ok := r.Context().Value(requestLogKey{}).(*requestLog); ok {
		entry.attrs = append(entry.attrs, attrs...)
	}
}

// Добавляет строковое поле с пользовательским вводом. Пустые значения не пишутся
func addLogString(r *http.Request, key, value string) {
	if value != "" {
		addLogAttrs(r, slog.String(key, truncateLogValue(value)))
	}
}

// Запоминает код ответа
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

// Для http.ResponseController
func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Запросы, которые не пишутся в access-лог при успешном ответе
func isQuietRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/static/") {
		return true
	}
	// Пробы Kubernetes
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		return true
	}
	// Опрос метрик раз в несколько секунд
	if r.URL.Path == "/metrics" {
		return true
	}
	return strings.HasPrefix(r.UserAgent(), "kube-probe/")
}

// Маршрут запроса для текста сообщения. Сам путь задает клиент, и в нем может
// оказаться адрес, поэтому в msg идет шаблон маршрута, а путь - в поле path
func routeName(r *http.Request) string {
	if r.Pattern != "" {
		// "{$}" в шаблоне означает точное совпадение пути
		return strings.Replace(r.Pattern, "{$}", "", 1)
	}
	return r.Method + " (no route)"
}

// Пишет одну строку на запрос и перехватывает панику обработчика, чтобы
// стектрейс попал в лог одним событием, а не десятками текстовых строк
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := requestID(r)
		w.Header().Set("X-Request-Id", id)

		entry := &requestLog{}
		r = r.WithContext(context.WithValue(r.Context(), requestLogKey{}, entry))
		recorder := &statusRecorder{ResponseWriter: w}
		log := componentLogger("http")

		defer func() {
			recovered := recover()
			if recovered == http.ErrAbortHandler {
				// Так net/http просит молча оборвать соединение
				panic(recovered)
			}
			if recovered != nil {
				if recorder.status == 0 {
					http.Error(recorder, "Internal Server Error", http.StatusInternalServerError)
				}
				stack := string(debug.Stack())
				if len(stack) > maxStacktraceLen {
					stack = stack[:maxStacktraceLen] + "..."
				}
				log.LogAttrs(r.Context(), slog.LevelError, "panic while handling "+routeName(r),
					slog.String("error", truncateLogValue(fmt.Sprint(recovered))),
					slog.String("stacktrace", stack),
					slog.String("request_id", id),
					slog.String("remote_addr", clientAddr(r)),
				)
			}

			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			duration := time.Since(start)
			recordRequest(routeName(r), status, duration)

			if status < http.StatusBadRequest && isQuietRequest(r) {
				return
			}

			level := slog.LevelInfo
			switch {
			case status >= http.StatusInternalServerError:
				level = slog.LevelError
			case status >= http.StatusBadRequest:
				level = slog.LevelWarn
			}

			attrs := []slog.Attr{
				slog.String("request_id", id),
				slog.String("remote_addr", clientAddr(r)),
				slog.String("method", r.Method),
				slog.String("path", truncateLogValue(r.URL.Path)),
				slog.Int("status", status),
				slog.Int64("duration_ms", duration.Milliseconds()),
			}
			attrs = append(attrs, entry.attrs...)

			// Параметры запроса только в полях: в них бывают адреса
			msg := fmt.Sprintf("%s -> %d in %dms", routeName(r), status, duration.Milliseconds())
			log.LogAttrs(r.Context(), level, msg, attrs...)
		}()

		next.ServeHTTP(recorder, r)
	})
}
