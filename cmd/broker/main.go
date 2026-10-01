package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"example.com/pingfederate-graph-broker/internal/broker"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if strings.EqualFold(os.Getenv("BROKER_LOG_LEVEL"), "debug") {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if err := run(logger); err != nil {
		logger.Error("broker_stopped", "error", err.Error())
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	cfg, err := broker.LoadConfig()
	if err != nil {
		return err
	}
	store, err := broker.OpenStore(cfg.DataDir, cfg.Key)
	if err != nil {
		return err
	}
	defer store.Close()
	app := broker.New(cfg, store, logger)
	srv := &http.Server{Addr: cfg.Listen, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { logger.Info("broker_listening", "address", cfg.Listen); done <- srv.ListenAndServe() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}
