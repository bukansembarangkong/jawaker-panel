package doctor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ControllerOptions supplies what the controller checks need.
//
// Everything is optional, and a nil field produces a SKIPPED check naming what
// was missing rather than a failure. That distinction is the point: an operator
// diagnosing a host where the database is not configured should read "database
// not configured", not a fabricated fault that sends them looking for a broken
// server.
type ControllerOptions struct {
	// Config is the validated configuration. Nil skips the configuration detail.
	Config *config.Config
	// DB is the control-plane pool. Nil skips every database-backed check.
	DB *pgxpool.Pool
	// Secrets is the secret store. Nil skips the CA and secret-key checks.
	Secrets *secret.Store
	// ListenAddr overrides where the listener check probes, so an operator can
	// check an address other than the configured one. Empty uses Config.
	ListenAddr string
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
}

// Controller checks the control plane.
//
// The checks are ordered by DEPENDENCY: configuration, then the database, then
// the things that live inside it. Reading the report top to bottom therefore
// follows the cause, and the first failure explains the skips below it.
func Controller(ctx context.Context, version string, opts ControllerOptions) Report {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return Run(ctx, "controller", version, now,
		Diagnose("build", checkBuild),
		Diagnose("configuration", checkConfiguration(opts.Config)),
		Diagnose("database", checkDatabase(opts.DB)),
		Diagnose("migrations", checkMigrations(opts.DB)),
		Diagnose("secret-keys", checkSecretKeys(opts.Secrets)),
		Diagnose("certificate-authorities", checkAuthorities(opts.DB, opts.Secrets, now)),
		Diagnose("listener-port", checkListenerPort(opts.Config, opts.ListenAddr)),
		Diagnose("disk", checkDisk),
	)
}

// checkBuild always passes. It exists so a report always states which runtime and
// platform produced it: a report pasted into an incident is not actionable
// without that, and a cgo-enabled binary where the release pipeline builds
// CGO_ENABLED=0 means the host is not running the artifact the pipeline produced.
func checkBuild(context.Context) Check {
	cgo := "disabled"
	if cgoEnabled {
		cgo = "enabled"
	}
	return ok("build",
		fmt.Sprintf("built with %s for %s/%s, cgo %s", runtime.Version(), runtime.GOOS, runtime.GOARCH, cgo),
		map[string]any{
			"go_version": runtime.Version(),
			"goos":       runtime.GOOS,
			"goarch":     runtime.GOARCH,
			"cgo":        cgoEnabled,
		})
}

// checkConfiguration reports the effective, non-secret configuration.
//
// The DSN goes through Config.RedactedDSN rather than being printed raw: a
// diagnostic report gets pasted into issue trackers, and a database password in
// a bug report is a disclosure that outlives the incident.
func checkConfiguration(cfg *config.Config) CheckFunc {
	return func(context.Context) Check {
		if cfg == nil {
			return skip("configuration", "no configuration was supplied to doctor; "+
				"set the JAWAKER_* environment variables and run it again")
		}
		evidence := map[string]any{
			"listen_addr":          cfg.ListenAddr,
			"log_level":            cfg.LogLevel,
			"log_format":           cfg.LogFormat,
			"database_configured":  cfg.DatabaseURL != "",
			"secret_key_versions":  len(cfg.SecretKeys),
			"run_migrations":       cfg.RunMigrations,
			"cookie_secure":        cfg.CookieSecure,
			"max_body_bytes":       cfg.MaxBodyBytes,
			"max_header_bytes":     cfg.MaxHeaderBytes,
			"trusted_origins":      len(cfg.TrustedOrigins),
			"request_timeout_secs": cfg.RequestTimeoutSeconds,
		}
		if cfg.DatabaseURL != "" {
			evidence["database_dsn"] = cfg.RedactedDSN()
		}
		// The insecure-cookie override is reported as a warning rather than
		// listed as a fact: it is a deliberate development switch that would be a
		// session-hijack enabler in production, and an operator running doctor
		// may have forgotten they set it.
		if cfg.CookieAllowInsecure && !cfg.CookieSecure {
			return warn("configuration",
				"session cookies may travel over plaintext HTTP (JAWAKER_COOKIE_ALLOW_INSECURE is set); "+
					"this is a development switch and must not be used in production", evidence)
		}
		return ok("configuration", "environment configuration is valid and complete", evidence)
	}
}

// checkDatabase verifies connectivity and reports pool utilization.
func checkDatabase(pool *pgxpool.Pool) CheckFunc {
	return func(ctx context.Context) Check {
		if pool == nil {
			return skip("database", "no database is configured (JAWAKER_DATABASE_URL is empty); "+
				"authentication, node management and every database-backed feature are unavailable")
		}
		var version string
		if err := pool.QueryRow(ctx, `SELECT version()`).Scan(&version); err != nil {
			// A genuine failure rather than a skip: a pool exists, so a DSN was
			// set and expected to work. Reporting this as "could not run" would
			// disguise a real outage as a missing configuration.
			return fail("database", fmt.Sprintf("the database is unreachable: %v", err), nil)
		}
		stat := pool.Stat()
		return ok("database", "connected to PostgreSQL",
			map[string]any{
				"server_version": version,
				"total_conns":    stat.TotalConns(),
				"acquired_conns": stat.AcquiredConns(),
				"idle_conns":     stat.IdleConns(),
				"max_conns":      stat.MaxConns(),
				"constructing":   stat.ConstructingConns(),
			})
	}
}

// checkMigrations reports the schema's position relative to the embedded set.
//
// It calls Migrator.Status, which is read-only. A diagnostic must not be able to
// change what it is diagnosing: applying a pending migration here would repair
// the schema and then report that nothing was wrong.
func checkMigrations(pool *pgxpool.Pool) CheckFunc {
	return func(ctx context.Context) Check {
		if pool == nil {
			return skip("migrations", "no database is configured, so the schema cannot be inspected")
		}
		migrator, err := migrate.New(migrations.FS, slog.New(slog.DiscardHandler))
		if err != nil {
			return fail("migrations", fmt.Sprintf("the embedded migration set is invalid: %v", err), nil)
		}
		status, err := migrator.Status(ctx, pool)
		if err != nil {
			return fail("migrations", fmt.Sprintf("the schema could not be inspected: %v", err), nil)
		}
		evidence := map[string]any{
			"total":       status.Total,
			"applied":     status.Applied,
			"pending":     status.Pending,
			"tampered":    status.Tampered,
			"unknown":     status.Unknown,
			"initialized": status.Initialized,
		}
		switch {
		case len(status.Tampered) > 0:
			// The most serious state: released history was edited, so the binary
			// and the database disagree about what a migration CONTAINS. Running
			// migrations cannot fix that, which is why it is a failure.
			return fail("migrations",
				fmt.Sprintf("%d applied migration(s) no longer match their files (%v); released "+
					"migrations are immutable and this must be resolved by hand",
					len(status.Tampered), status.Tampered), evidence)
		case !status.Initialized:
			return warn("migrations",
				fmt.Sprintf("the database has never been migrated (%d pending); set "+
					"JAWAKER_RUN_MIGRATIONS=true or run the controller with -migrate-only",
					len(status.Pending)), evidence)
		case len(status.Pending) > 0:
			return warn("migrations",
				fmt.Sprintf("%d of %d migration(s) are pending: %v",
					len(status.Pending), status.Total, status.Pending), evidence)
		case len(status.Unknown) > 0:
			// Not a failure in itself: a newer build migrated this schema and
			// upgrading forward is supported. What the operator must not do is
			// run an older binary against it, and this is how they find out.
			return warn("migrations",
				fmt.Sprintf("the schema carries %d migration(s) this build does not include, so an "+
					"older binary is running against a newer schema: %v",
					len(status.Unknown), status.Unknown), evidence)
		default:
			return ok("migrations",
				fmt.Sprintf("schema is up to date at %d applied migration(s)", status.Applied), evidence)
		}
	}
}

// checkSecretKeys verifies the master key material the process actually loaded.
func checkSecretKeys(store *secret.Store) CheckFunc {
	return func(context.Context) Check {
		if store == nil {
			return skip("secret-keys",
				"no secret store is configured (JAWAKER_SECRET_KEY_V<n> is unset, or it is malformed, "+
					"or the database is unavailable); second factors and the certificate authorities "+
					"cannot work")
		}
		versions := store.KeyVersions()
		active := store.CurrentKeyVersion()
		evidence := map[string]any{"key_versions": versions, "active_version": active}
		if len(versions) == 0 {
			return fail("secret-keys", "the secret store loaded no master keys", evidence)
		}
		if len(versions) == 1 {
			// One key is not a fault, but a rotation cannot be performed with it:
			// new ciphertext and old ciphertext must both be readable for the
			// duration of the rotation. Stated because it is a decision an
			// operator has to make before they need it.
			return warn("secret-keys",
				fmt.Sprintf("only one master key version (%d) is loaded; a rotation requires the old "+
					"and the new key present together", versions[0]), evidence)
		}
		return ok("secret-keys",
			fmt.Sprintf("%d master key version(s) loaded, currently writing with %d",
				len(versions), active), evidence)
	}
}

// checkAuthorities reads both certificate authorities from the secret store.
//
// It uses LoadAuthority, NOT EnsureAuthority, and that difference is the whole
// design of this check. EnsureAuthority CREATES a missing root, so a doctor built
// on it would silently repair the exact condition it was asked to report — in the
// one case where the operator most needs to know, because minting a new root
// invalidates every certificate already issued to every enrolled node.
func checkAuthorities(pool *pgxpool.Pool, store *secret.Store, now func() time.Time) CheckFunc {
	return func(ctx context.Context) Check {
		if pool == nil || store == nil {
			return skip("certificate-authorities",
				"the database or the secret store is unavailable, so the authorities cannot be read")
		}
		authority, err := nodes.LoadAuthority(ctx, nodes.AuthorityOptions{DB: pool, Secrets: store, Now: now})
		if err != nil {
			if errors.Is(err, nodes.ErrNoAuthority) {
				return fail("certificate-authorities",
					fmt.Sprintf("the internal certificate authority is missing (%v); node enrollment and "+
						"the node-facing TLS listener cannot work, and creating a NEW root would "+
						"invalidate every certificate already issued", err), nil)
			}
			return fail("certificate-authorities",
				fmt.Sprintf("the certificate authorities could not be loaded: %v", err), nil)
		}

		// Read each authority's window through the certificate it exposes, rather
		// than adding accessors to the nodes package for a diagnostic's benefit.
		controllerCert, err := pki.DecodeCertPEM(string(authority.ControllerCertPEM()))
		if err != nil {
			return fail("certificate-authorities",
				fmt.Sprintf("the controller authority's certificate cannot be parsed: %v", err), nil)
		}
		nodeCert, err := pki.DecodeCertPEM(string(authority.NodeCertPEM()))
		if err != nil {
			return fail("certificate-authorities",
				fmt.Sprintf("the node authority's certificate cannot be parsed: %v", err), nil)
		}

		evidence := map[string]any{
			"controller_fingerprint": authority.ControllerFingerprint(),
			"node_fingerprint":       authority.NodeFingerprint(),
			"controller_not_after":   controllerCert.NotAfter.UTC(),
			"node_not_after":         nodeCert.NotAfter.UTC(),
			"controller_remaining":   remaining(controllerCert.NotAfter.Sub(now())),
			"node_remaining":         remaining(nodeCert.NotAfter.Sub(now())),
		}

		controllerLeft := controllerCert.NotAfter.Sub(now())
		nodeLeft := nodeCert.NotAfter.Sub(now())
		switch {
		case controllerLeft <= 0 || nodeLeft <= 0:
			// An expired authority cannot sign, so every enrollment fails and
			// every issued certificate stops verifying. Reported as the countdown
			// it is rather than as an unexplained outage.
			return fail("certificate-authorities",
				fmt.Sprintf("a certificate authority has EXPIRED (controller %s, node %s)",
					remaining(controllerLeft), remaining(nodeLeft)), evidence)
		case controllerLeft < certRenewalWindow || nodeLeft < certRenewalWindow:
			return warn("certificate-authorities",
				fmt.Sprintf("a certificate authority expires within %s (controller %s, node %s); every "+
					"certificate it issued becomes unverifiable at that point, and replacing a root is "+
					"a fleet-wide operation rather than a restart",
					remaining(certRenewalWindow), remaining(controllerLeft), remaining(nodeLeft)), evidence)
		default:
			return ok("certificate-authorities",
				fmt.Sprintf("both authorities are present and valid (controller expires in %s, node in %s)",
					remaining(controllerLeft), remaining(nodeLeft)), evidence)
		}
	}
}

// checkListenerPort reports whether the configured listener address can be bound,
// WITHOUT leaving it bound.
//
// It binds and immediately closes, because the question an operator actually has
// is "is something else already on my port?". A doctor that held the port would
// prevent the controller it is diagnosing from starting, and the bind is the only
// way to answer at all.
func checkListenerPort(cfg *config.Config, override string) CheckFunc {
	return func(context.Context) Check {
		addr := override
		if addr == "" && cfg != nil {
			addr = cfg.ListenAddr
		}
		if addr == "" {
			return skip("listener-port", "no listener address was supplied, so nothing could be probed")
		}
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
		if err != nil {
			return fail("listener-port",
				fmt.Sprintf("%s cannot be bound: %v; if the controller is already running this is "+
					"expected, and otherwise another process holds the port", addr, err), nil)
		}
		bound := ln.Addr().String()
		_ = ln.Close()
		return ok("listener-port", fmt.Sprintf("%s is free to bind", bound),
			map[string]any{"address": bound})
	}
}

// checkDisk reports free space on the filesystem holding the working directory.
//
// It declines rather than guessing on platforms where free space is not
// implemented: a fabricated figure in a diagnostic is worse than an honest skip,
// because it is acted upon.
func checkDisk(context.Context) Check {
	if runtime.GOOS != "linux" {
		return skip("disk", "free-space reporting is implemented for Linux only")
	}
	wd, err := os.Getwd()
	if err != nil {
		return skip("disk", fmt.Sprintf("the working directory could not be resolved: %v", err))
	}
	free, total, err := diskFree(wd)
	if err != nil {
		return skip("disk", fmt.Sprintf("free space could not be read for %s: %v", wd, err))
	}
	evidence := map[string]any{
		"path":        wd,
		"free_bytes":  free,
		"total_bytes": total,
		"free_human":  humanBytes(free),
		"total_human": humanBytes(total),
	}
	// 5% because PostgreSQL keeps its own reserve and refuses to start below it,
	// so a controller that cannot write is worse than one warned early.
	if total > 0 && free*100/total < 5 {
		return warn("disk",
			fmt.Sprintf("only %s free of %s on %s", humanBytes(free), humanBytes(total), wd), evidence)
	}
	return ok("disk", fmt.Sprintf("%s free of %s on %s", humanBytes(free), humanBytes(total), wd), evidence)
}

// certRenewalWindow is how close to expiry an authority may be before doctor
// reports it. An authority outlives every certificate it signed, so this is a
// long window: replacing a root is a deliberate, fleet-wide operation.
const certRenewalWindow = pki.DefaultCALifetime / 6
