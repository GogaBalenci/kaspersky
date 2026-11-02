package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/balenci/kaspersky/internal/config"
	"github.com/balenci/kaspersky/internal/platform/database"
	"github.com/balenci/kaspersky/internal/repository/postgres"
	"github.com/balenci/kaspersky/internal/service"
	httptransport "github.com/balenci/kaspersky/internal/transport/http"
	"github.com/balenci/kaspersky/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(context.Background(), logger); err != nil {
		logger.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}

	pool, err := database.NewPostgresPool(ctx, settings.DatabaseURL, settings.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := migrations.Apply(ctx, pool); err != nil {
		return err
	}

	repository := postgres.NewThreatRepository(pool)
	handler := httptransport.NewHandlerWithOptions(service.NewThreatService(repository), httptransport.HandlerOptions{
		APIKey:                settings.APIKey,
		RequireAPIKeyForReads: settings.RequireAPIKeyForReads,
		HealthChecker:         pool,
		Logger:                logger,
	})
	server := &http.Server{
		Addr: settings.HTTPAddress,
		Handler: httptransport.NewRouter(handler, httptransport.RouterOptions{
			Logger:            logger,
			RequestsPerMinute: settings.RateLimit.RequestsPerMinute,
			RateLimitBurst:    settings.RateLimit.Burst,
			RequestTimeout:    settings.RequestTimeout,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      config.MaxRequestTimeout,
		IdleTimeout:       60 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		if settings.TLSCertFile != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			logger.Info("HTTPS server started", "address", settings.HTTPAddress)
			serverErrors <- server.ListenAndServeTLS(settings.TLSCertFile, settings.TLSKeyFile)
			return
		}
		logger.Info("HTTP server started", "address", settings.HTTPAddress)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-shutdownContext.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
