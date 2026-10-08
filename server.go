package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Сколько ждать завершения текущих запросов при остановке
const shutdownTimeout = 20 * time.Second

func newServer(handler http.Handler) *http.Server {
	// Таймауты не дают медленным клиентам удерживать соединения бесконечно
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// Внутренние ошибки net/http тоже должны выходить в JSON
		ErrorLog: slog.NewLogLogger(componentLogger("http").Handler(), slog.LevelError),
	}
}

// Обслуживает запросы, пока контекст не отменен (SIGTERM от Kubernetes).
// После отмены перестает принимать соединения и дожидается текущих запросов,
// чтобы выкат и переезд пода не обрывали ответы пользователям
func serve(ctx context.Context, listener net.Listener, handler http.Handler, grace time.Duration) error {
	log := componentLogger("server")
	server := newServer(handler)

	failed := make(chan error, 1)
	go func() {
		failed <- server.Serve(listener)
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	log.Info("shutdown requested, waiting for requests to finish", "timeout_ms", grace.Milliseconds())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		// Время вышло: закрываем оставшиеся соединения принудительно
		_ = server.Close()
		return errors.Join(errors.New("shutdown timed out, connections closed"), err)
	}

	log.Info("server stopped")
	return nil
}
