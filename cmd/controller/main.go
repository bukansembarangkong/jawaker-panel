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
	// A subcommand gate rather than a flag: `doctor` produces a report and exits,
	// so it must not share the listener flags the server needs. It is checked
	// before Parse so `jawaker-controller doctor` does not try to bind anything.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			return runDoctor(os.Args[2:])
		case "version", "-version", "--version":
			fmt.Println(version.String())
			return nil
		}
	}

	migrateOnly := flag.Bool("migrate-only", false, "apply pending database migrations and exit")
	nodeListenAddr := flag.String("node-listen", "",
		"host:port for the node-facing mutual-TLS listener (empty disables it; nodes will not be able to report)")
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

	// The node-facing mutual-TLS listener runs on its OWN port, separate from the
	// public API. It is started only when the node subsystem came up: without an
	// authority there is nothing to verify a node against, and a listener that
	// refused every connection would look like a network fault.
	var nodeListenerErr chan error
	if assembled.NodeListener != nil {
		if *nodeListenAddr == "" {
			logger.Warn("node listener not started: -node-listen is empty; nodes will be unable to report")
		} else {
			nodeListenerErr = make(chan error, 1)
			listener := assembled.NodeListener
			addr := *nodeListenAddr
			go func() { nodeListenerErr <- listener.ListenAndServe(ctx, addr) }()
		}
	}

	// The site background worker executes enqueued site.apply jobs. It shares
	// the process context: on shutdown Run returns after the in-flight handler
	// finishes, and an unfinished job's lease expires so another instance can
	// reclaim it. Errors are logged rather than fatal — a worker whose claim
	// loop hit a transient database error must not take down the API.
	if assembled.SiteWorker != nil {
		worker := assembled.SiteWorker
		go func() {
			if err := worker.Run(ctx); err != nil {
				logger.Error("site worker stopped with an error", "error", err)
			}
		}()
	}

	// The app background worker executes enqueued app.deploy jobs.
	if assembled.AppWorker != nil {
		worker := assembled.AppWorker
		go func() {
			if err := worker.Run(ctx); err != nil {
				logger.Error("app worker stopped with an error", "error", err)
			}
		}()
	}

	// The database background worker executes enqueued database.* jobs.
	if assembled.DatabaseWorker != nil {
		worker := assembled.DatabaseWorker
		go func() {
			if err := worker.Run(ctx); err != nil {
				logger.Error("database worker stopped with an error", "error", err)
			}
		}()
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
	case err := <-nodeListenerErr:
		return fmt.Errorf("node listener failed: %w", err)
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
