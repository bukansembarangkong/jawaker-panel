package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/db"
	"github.com/bukansembarangkong/jawaker-panel/internal/doctor"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/internal/version"
	"github.com/jackc/pgx/v5/pgxpool"
)

// doctorTimeout bounds the whole report. It exists because doctor connects to the
// database and binds a port, and a black-holed host would otherwise hang with no
// output at all — the one outcome an operator cannot work with.
const doctorTimeout = 30 * time.Second

// runDoctor produces a diagnostic report and exits.
//
// It returns an error when a check FAILED, so a monitoring system or an install
// script can branch on it. Warnings and skips still succeed: a warning is
// survivable by definition, and a skip means the check was not applicable rather
// than that the installation is broken.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON instead of text")
	listenAddr := fs.String("listen-addr", "", "address to probe instead of the configured one")
	noDB := fs.Bool("no-database", false, "skip every database-backed check")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		// A configuration error is itself a finding, but doctor must still report
		// on the database and the filesystem. The error goes to stderr rather than
		// being returned, and the checks that need the configuration report a skip
		// naming what was missing.
		fmt.Fprintf(os.Stderr, "jawaker-controller: configuration could not be loaded: %v\n\n", cfgErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), doctorTimeout)
	defer cancel()

	var (
		pool        *pgxpool.Pool
		secretStore *secret.Store
	)
	if cfg != nil && cfg.DatabaseURL != "" && !*noDB {
		// A failed connection is NOT fatal here, unlike at startup: doctor's job
		// is to report the failure, and returning early would deny the operator
		// the rest of the report.
		connected, err := db.Connect(ctx, cfg.DatabaseURL, db.DefaultPoolConfig())
		if err != nil {
			fmt.Fprintf(os.Stderr, "jawaker-controller: database connection failed: %v\n\n", err)
		} else {
			pool = connected
			defer pool.Close()
		}

		// The secret store is built only when both a pool and keys are available,
		// because secret.New requires them; its absence becomes a skipped check
		// naming which input was missing.
		if pool != nil && cfg.HasSecretKeys() {
			secretStore, err = secret.New(secret.Options{DB: pool, Keys: cfg.SecretKeys})
			if err != nil {
				fmt.Fprintf(os.Stderr, "jawaker-controller: secret store unavailable: %v\n\n", err)
				secretStore = nil
			}
		}
	}

	report := doctor.Controller(ctx, version.String(), doctor.ControllerOptions{
		Config:     cfg,
		DB:         pool,
		Secrets:    secretStore,
		ListenAddr: *listenAddr,
	})

	if *asJSON {
		raw, err := report.JSON()
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
		fmt.Println(string(raw))
	} else {
		fmt.Print(report.Text())
	}

	if !report.Healthy() {
		return errors.New("one or more checks FAILED")
	}
	return nil
}
