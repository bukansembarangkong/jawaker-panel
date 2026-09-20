// Command jawaker-controller is the JAWAKER control-plane service.
//
// Startup order: config → logger → (optional) database pool → migrations →
// HTTP server with graceful shutdown. With no JAWAKER_DATABASE_URL the
// controller still boots and serves health/version so operators can diagnose
// a misconfigured installation (ARCHITECTURE.md §13: graceful degradation);
// with a configured-but-unreachable database it fails fast rather than
// silently running degraded.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/controller"
	"github.com/bukansembarangkong/jawaker-panel/internal/db"
	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/logging"
	"github.com/bukansembarangkong/jawaker-panel/internal/version"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// shutdownTimeout bounds draining in-flight requests after SIGTERM/SIGINT.
const shutdownTimeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "jawaker-controller:", err)
		os.Exit(1)
	}
}

func run() error {
	migrateOnly := flag.Bool("migrate-only", false, "apply pending database migrations and exit")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{
		Level:     cfg.LogLevel,
		Format:    cfg.LogFormat,
		Component: "controller",
	})
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	logger.Info("starting jawaker-controller", "version", version.String(), "config", cfg.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var pool *pgxpool.Pool
	if cfg.DatabaseURL != "" {
		pool, err = db.Connect(ctx, cfg.DatabaseURL, db.DefaultPoolConfig())
		if err != nil {
			// Fail fast: the operator explicitly configured a DSN; silently
			// continuing would hide misconfiguration.
			logger.Error("database connection failed", "error", err, "dsn", cfg.RedactedDSN())
			return err
		}
		defer pool.Close()
		logger.Info("database connected", "dsn", cfg.RedactedDSN())

		if cfg.RunMigrations || *migrateOnly {
			if err = applyMigrations(ctx, pool, logger); err != nil {
				return err
			}
		}
	} else {
		logger.Warn("JAWAKER_DATABASE_URL is empty; starting without database (health/version only)")
	}

	if *migrateOnly {
		if pool == nil {
			return errors.New("-migrate-only requires JAWAKER_DATABASE_URL")
		}
		logger.Info("migrate-only completed")
		return nil
	}

	assembled, err := controller.Build(controller.Options{Config: cfg, Logger: logger, DB: pool, Context: ctx})
	if err != nil {
		return err
	}
	handler := assembled.HTTP
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second, // slowloris guard (SECURITY.md §11)
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", cfg.ListenAddr)
		serverErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server failed: %w", err)
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

func applyMigrations(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	migrator, err := migrate.New(migrations.FS, logger)
	if err != nil {
		logger.Error("migration set is invalid", "error", err)
		return err
	}
	applied, err := migrator.Up(ctx, pool)
	if err != nil {
		logger.Error("migrations failed", "error", err)
		return err
	}
	if len(applied) > 0 {
		logger.Info("migrations applied", "count", len(applied), "migrations", applied)
	} else {
		logger.Debug("migrations up to date")
	}
	return nil
}
