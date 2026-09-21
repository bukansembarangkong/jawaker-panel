// Package controller assembles the control-plane HTTP surface.
//
// It exists so the WIRING is testable. main.go starts a process and cannot be
// imported; if the handler assembly lived there, the composition of session
// middleware, route protection, and the secret subsystem would only ever be
// verified by hand. Putting it here means an integration test can drive the
// exact same stack production runs.
package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apps"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/backups"
	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/databases"
	"github.com/bukansembarangkong/jawaker-panel/internal/eventstream"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/projects"
	"github.com/bukansembarangkong/jawaker-panel/internal/ratelimit"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/internal/sites"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options assembles a controller handler.
type Options struct {
	// Config is the validated runtime configuration. Required.
	Config *config.Config
	// Logger receives request-scoped and startup logs. Required.
	Logger *slog.Logger
	// DB is the control-plane pool. Nil disables database-backed routes while
	// health and version keep answering (ARCHITECTURE.md §13: graceful
	// degradation).
	DB *pgxpool.Pool
	// Now supplies the clock for session lifetime and rate limiting. Zero means
	// time.Now. Injected by tests.
	Now func() time.Time
	// PasswordParams overrides the argon2id parameters. Zero value uses
	// password.DefaultParams(). Tests use cheaper parameters.
	PasswordParams *password.Params
	// Context bounds startup work that reaches external systems. Nil means
	// context.Background().
	//
	// It exists because building the node subsystem creates the internal
	// certificate authorities on first run, which writes to PostgreSQL. Using
	// context.Background() internally would make that write uninterruptible, so a
	// stuck database would hang startup with no way to cancel it.
	Context context.Context
}

// Handler is the assembled stack.
type Handler struct {
	// HTTP is the fully wrapped handler to serve.
	HTTP http.Handler
	// Secrets is the secret store, nil when secret-backed features are disabled.
	Secrets *secret.Store
	// AuthRoutesMounted reports whether /api/v1/auth/* is registered.
	AuthRoutesMounted bool
	// Events is the SSE broker publishers use to push live updates to connected
	// clients. Nil when the stream routes are not mounted.
	Events *eventstream.Broker
	// EventStreamMounted reports whether /api/v1/events/* is registered.
	EventStreamMounted bool
	// NodeRoutesMounted reports whether /api/v1/servers/* is registered. It is
	// false when no secret keys or database are configured, or when the
	// certificate authority could not be prepared, so a caller can distinguish
	// "not configured" from "mounted but empty".
	NodeRoutesMounted bool
	// SiteRoutesMounted reports whether /api/v1/projects/{project_id}/sites/*
	// is registered. Requires both database and secret keys.
	SiteRoutesMounted bool
	// AppRoutesMounted reports whether /api/v1/projects/{project_id}/apps/*
	// is registered.
	AppRoutesMounted bool
	// DatabaseRoutesMounted reports whether /api/v1/projects/{project_id}/databases/*
	// is registered.
	DatabaseRoutesMounted bool
	// BackupRoutesMounted reports whether /api/v1/projects/{project_id}/backup-*
	// is registered.
	BackupRoutesMounted bool
	// ProjectRoutesMounted reports whether /api/v1/projects/* is registered.
	ProjectRoutesMounted bool
	// JobRoutesMounted reports whether /api/v1/jobs/* is registered.
	JobRoutesMounted bool
	// Sites is the hosted sites inventory store.
	Sites *sites.Store
	// Apps is the applications inventory store.
	Apps *apps.Store
	// Databases is the managed databases inventory store.
	Databases *databases.Store
	// Backups is the backup plans and runs store.
	Backups *backups.Store
	// Projects is the tenant boundary store.
	Projects *projects.Store
	// SiteWorker is the background jobs worker executing configuration applies
	// and deployments, nil when background processing is disabled.
	SiteWorker *jobs.Worker
	// AppWorker is the background jobs worker executing application deployments.
	AppWorker *jobs.Worker
	// DatabaseWorker is the background jobs worker executing managed database
	// provisioning, dumps, restores, and deletes.
	DatabaseWorker *jobs.Worker
	// BackupWorker executes backup.run/verify/restore/delete jobs.
	BackupWorker *jobs.Worker
	// BackupScheduler enqueues scheduled backup runs and enforces retention.
	BackupScheduler *BackupScheduler
	// Authority is the installation's certificate authority, nil when the node
	// subsystem is disabled. Exposed so main can report fingerprints at startup
	// and so the node-agent listener can reuse it instead of loading the
	// roots a second time.
	Authority *nodes.Authority
	// NodeListener is the node-facing mutual-TLS listener, nil when the node
	// subsystem is disabled. It is a SEPARATE listener from the public API: a
	// node authenticates with a client certificate, and mixing that credential
	// class with session-authenticated browser traffic on one port would mean one
	// set of middleware reasons about both.
	NodeListener *nodes.NodeListener
	// Dispatcher performs operations on enrolled nodes, nil when the node
	// subsystem is disabled.
	Dispatcher *nodes.Dispatcher
	// Store is the node inventory, exposed so a caller can read it without
	// building a second one over the same pool.
	Store *nodes.Store
	// CookieConfig is the session/CSRF cookie attributes in effect, so callers
	// (and tests) can assert what clients will actually receive.
	CookieConfig auth.CookieConfig
}

// EventStreamPath is the route prefix for SSE subscriptions. It is exported so
// the middleware configuration and any tests refer to one constant rather than
// three copies of the string.
const EventStreamPath = "/api/v1/events/"

// Build assembles the HTTP surface.
//
// The authentication routes need BOTH a database and a secret master key: the
// former to store identities, the latter to seal TOTP secrets. When either is
// missing those routes are not mounted and the reason is logged once. That is
// deliberate — a half-configured panel that accepts logins but cannot verify a
// second factor is worse than one that plainly reports what it lacks.
//
// A MALFORMED secret key, by contrast, is a startup error rather than a warning:
// that is a misconfiguration an operator believes they fixed, and starting
// anyway would silently disable second factors.
func Build(opts Options) (*Handler, error) {
	if opts.Config == nil {
		return nil, errors.New("controller: config is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("controller: logger is required")
	}
	cfg := opts.Config
	logger := opts.Logger

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	cookies := auth.DefaultCookieConfig()
	cookies.Secure = cfg.CookieSecure
	cookies.AllowInsecure = cfg.CookieAllowInsecure

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	params := password.DefaultParams()
	if opts.PasswordParams != nil {
		params = *opts.PasswordParams
	}

	out := &Handler{CookieConfig: cookies}

	var (
		register     func(*http.ServeMux)
		sessionLayer func(http.Handler) http.Handler
		// nodeRoutes is set only when the node subsystem came up; a nil value
		// means its routes are not mounted at all.
		nodeRoutes func(*http.ServeMux)
	)

	switch {
	case opts.DB == nil:
		logger.Warn("authentication routes disabled: JAWAKER_DATABASE_URL is not configured")
	case !cfg.HasSecretKeys():
		logger.Warn("authentication routes disabled: no JAWAKER_SECRET_KEY_V<n> is configured")
	default:
		secrets, err := secret.New(secret.Options{DB: opts.DB, Keys: cfg.SecretKeys})
		if err != nil {
			return nil, fmt.Errorf("controller: secret subsystem: %w", err)
		}

		csrf, err := auth.NewCSRF(cookies, cfg.TrustedOrigins)
		if err != nil {
			return nil, fmt.Errorf("controller: csrf: %w", err)
		}

		// Login and bootstrap are rate limited per client address by the handler
		// set, independently of the per-account lockout (SECURITY.md §3, §11).
		sessionOpts := authsession.Options{
			DB:      opts.DB,
			Logger:  logger,
			Cookies: cookies,
			Policy:  identity.DefaultSessionPolicy(),
			Secrets: secrets,
			Now:     now,
		}
		handlers, err := authsession.NewHandlers(authsession.HandlerOptions{
			Options:       sessionOpts,
			CSRF:          csrf,
			Lockout:       authsession.DefaultLockoutPolicy(),
			PasswordHash:  params,
			LoginRate:     ratelimit.Options{Limit: cfg.LoginAttemptsPerMinute, Interval: time.Minute},
			BootstrapRate: ratelimit.Options{Limit: cfg.BootstrapAttemptsPerMinute, Interval: time.Minute},
		})
		if err != nil {
			return nil, fmt.Errorf("controller: auth handlers: %w", err)
		}

		// The session middleware wraps the WHOLE mux once, so every route sees a
		// resolved principal when a cookie is present. It never rejects, so
		// public routes stay reachable and carry their own explicit guards.
		sessionLayer = func(next http.Handler) http.Handler {
			return authsession.Middleware(sessionOpts, next)
		}
		out.Secrets = secrets
		out.AuthRoutesMounted = true

		// Live updates share the same authorization evaluator as the REST API,
		// so a topic cannot be readable over SSE while its data is forbidden
		// over HTTP. The params are the request's own, meaning an impersonated
		// or step-up-limited session is judged exactly as it would be elsewhere.
		broker := eventstream.New(eventstream.Options{})
		streamHandler, err := eventstream.NewHandler(eventstream.HandlerOptions{
			Broker: broker,
			Authorize: func(r *http.Request, topic string) bool {
				return authorizeTopic(r, topic, now)
			},
		})
		if err != nil {
			return nil, fmt.Errorf("controller: event stream handler: %w", err)
		}

		// The node subsystem needs the secret store for CA custody. Its routes are
		// mounted only when the authority is available: an installation whose CA
		// could not be prepared would otherwise serve a fleet UI whose every
		// action fails, which reads as a bug rather than as a missing configuration.
		//
		// EnsureAuthority (not LoadAuthority) is used here because this is a
		// startup path: on a fresh installation the roots must be created, and on
		// an existing one they are read back unchanged. The distinction is
		// recorded by the created flag below so the event is visible in the log
		// exactly once, at the moment it happens.
		authority, caCreated, caErr := nodes.EnsureAuthority(ctx, nodes.AuthorityOptions{
			DB:      opts.DB,
			Secrets: secrets,
			Now:     now,
		})
		switch {
		case caErr != nil:
			// Not fatal: authentication and the API still work, and refusing to
			// start would take down a running panel because of one subsystem.
			logger.Error("node management disabled: certificate authority unavailable",
				"error", caErr)
		default:
			if caCreated {
				// Fingerprints rather than the keys themselves: an operator needs
				// to be able to record WHICH root was created, never the key.
				logger.Info("internal certificate authorities created",
					"controller_fingerprint", authority.ControllerFingerprint(),
					"node_fingerprint", authority.NodeFingerprint())
			}
			nodeStore := nodes.NewStore(opts.DB, now)
			nodeHandlers, nodeErr := nodes.NewHandlers(nodes.HandlerOptions{
				Store:     nodeStore,
				Authority: authority,
				Audit:     opts.DB,
				Logger:    logger,
				Now:       now,
			})
			if nodeErr != nil {
				logger.Error("node management disabled: handlers could not be built", "error", nodeErr)
				break
			}

			// The node-facing listener is built here but STARTED by main, because
			// it binds its own port and a library that opens sockets is a library
			// that is hard to test and awkward to shut down.
			nodeListener, listenerErr := nodes.NewNodeListener(nodes.NodeListenerOptions{
				Handlers: nodeHandlers,
				Logger:   logger,
				Now:      now,
			})
			if listenerErr != nil {
				// Not fatal: the fleet API and enrollment endpoint still work over
				// the public listener; only the node-facing mTLS port is missing.
				logger.Error("node listener unavailable", "error", listenerErr)
			}

			dispatcher, dispatchErr := nodes.NewDispatcher(nodes.DispatchOptions{
				Authority: authority,
				Store:     nodeStore,
				Now:       now,
			})
			if dispatchErr != nil {
				logger.Error("node dispatch unavailable: operations on nodes cannot be performed", "error", dispatchErr)
			}

			nodeRoutes = nodeHandlers.Routes
			out.Authority = authority
			out.Store = nodeStore
			out.NodeListener = nodeListener
			out.Dispatcher = dispatcher
		}

		// Site management: the sites store over the same pool. These routes mount
		// whenever the database and secret keys are present — site CRUD does not
		// depend on the certificate authority. validate/apply answer 503 when the
		// dispatcher is nil (node subsystem unavailable), which the handler guards.
		out.Sites = sites.NewStore(opts.DB, now)
		siteHandlers, siteErr := NewSiteHandlers(SiteHandlerOptions{
			Sites:      out.Sites,
			Pool:       opts.DB,
			Dispatcher: out.Dispatcher,
			Logger:     logger,
			Audit:      opts.DB,
			Now:        now,
		})
		if siteErr != nil {
			return nil, fmt.Errorf("controller: site handlers: %w", siteErr)
		}
		siteRoutes := siteHandlers.Routes

		// The background worker that executes enqueued site.apply jobs. Without
		// it handleApplyConfig would enqueue work nobody ever claims, and the
		// API's 202 would be a promise the panel never keeps. It is built even
		// when the dispatcher is nil: the handler fails such jobs honestly
		// with dispatcher_unavailable rather than leaving them queued forever.
		siteWorker, workerErr := NewSiteApplyWorker(SiteWorkerOptions{
			Pool:       opts.DB,
			Sites:      out.Sites,
			Dispatcher: out.Dispatcher,
			Logger:     logger.With("component", "site-worker"),
		})
		if workerErr != nil {
			return nil, fmt.Errorf("controller: site worker: %w", workerErr)
		}
		out.SiteWorker = siteWorker

		out.Projects = projects.NewStore(opts.DB, now)
		projectHandlers, projErr := NewProjectHandlers(ProjectHandlerOptions{
			Projects: out.Projects,
			Pool:     opts.DB,
			Logger:   logger,
			Audit:    opts.DB,
			Now:      now,
		})
		if projErr != nil {
			return nil, fmt.Errorf("controller: project handlers: %w", projErr)
		}
		projectRoutes := projectHandlers.Routes

		// Application management: apps CRUD and deploy endpoint. The worker
		// is started even when the dispatcher is nil — it fails jobs honestly
		// with dispatcher_unavailable rather than leaving them queued forever.
		out.Apps = apps.NewStore(opts.DB, now)
		appHandlers, appErr := NewAppHandlers(AppHandlerOptions{
			Apps:       out.Apps,
			Pool:       opts.DB,
			Secrets:    out.Secrets,
			Dispatcher: out.Dispatcher,
			Logger:     logger,
			Audit:      opts.DB,
			Now:        now,
		})
		if appErr != nil {
			return nil, fmt.Errorf("controller: app handlers: %w", appErr)
		}
		appRoutes := appHandlers.Routes

		// Managed databases: CRUD, users, connection strings, metrics, dump
		// and restore endpoints. The database.* job workers arrive in PR-E;
		// jobs enqueued before that stay queued, which the jobs engine
		// reports honestly rather than silently dropping.
		out.Databases = databases.NewStore(opts.DB, now)
		dbHandlers, dbErr := NewDatabaseHandlers(DatabaseHandlerOptions{
			Databases:  out.Databases,
			Pool:       opts.DB,
			Secrets:    out.Secrets,
			Dispatcher: out.Dispatcher,
			Logger:     logger,
			Audit:      opts.DB,
			Now:        now,
		})
		if dbErr != nil {
			return nil, fmt.Errorf("controller: database handlers: %w", dbErr)
		}
		dbRoutes := dbHandlers.Routes

		// Backup plans (Phase 6): CRUD, manual runs, verification, restore, and
		// expiring download links. The backup.* job workers arrive in PR-E;
		// jobs enqueued before that stay queued, which the jobs engine reports
		// honestly rather than silently dropping.
		out.Backups = backups.NewStore(opts.DB, now)
		backupHandlers, backupErr := NewBackupHandlers(BackupHandlerOptions{
			Backups: out.Backups,
			Pool:    opts.DB,
			Logger:  logger,
			Audit:   opts.DB,
			Now:     now,
		})
		if backupErr != nil {
			return nil, fmt.Errorf("controller: backup handlers: %w", backupErr)
		}
		backupRoutes := backupHandlers.Routes

		appWorker, appWorkerErr := NewAppDeployWorker(AppWorkerOptions{
			Pool:       opts.DB,
			Apps:       out.Apps,
			Projects:   out.Projects,
			Secrets:    out.Secrets,
			Dispatcher: out.Dispatcher,
			Logger:     logger.With("component", "app-worker"),
		})
		if appWorkerErr != nil {
			return nil, fmt.Errorf("controller: app worker: %w", appWorkerErr)
		}
		out.AppWorker = appWorker

		dbWorker, dbWorkerErr := NewDatabaseWorker(DatabaseWorkerOptions{
			Pool:       opts.DB,
			Databases:  out.Databases,
			Dispatcher: out.Dispatcher,
			Logger:     logger.With("component", "database-worker"),
		})
		if dbWorkerErr != nil {
			return nil, fmt.Errorf("controller: database worker: %w", dbWorkerErr)
		}
		out.DatabaseWorker = dbWorker

		backupWorker, backupWorkerErr := NewBackupWorker(BackupWorkerOptions{
			Pool:       opts.DB,
			Backups:    out.Backups,
			Dispatcher: out.Dispatcher,
			Logger:     logger.With("component", "backup-worker"),
		})
		if backupWorkerErr != nil {
			return nil, fmt.Errorf("controller: backup worker: %w", backupWorkerErr)
		}
		out.BackupWorker = backupWorker

		backupScheduler, schedErr := NewBackupScheduler(BackupSchedulerOptions{
			Pool:    opts.DB,
			Backups: out.Backups,
			Logger:  logger.With("component", "backup-scheduler"),
		})
		if schedErr != nil {
			return nil, fmt.Errorf("controller: backup scheduler: %w", schedErr)
		}
		out.BackupScheduler = backupScheduler

		jobHandlers, jobErr := NewJobHandlers(JobHandlerOptions{
			Pool:   opts.DB,
			Logger: logger,
			Now:    now,
		})
		if jobErr != nil {
			return nil, fmt.Errorf("controller: job handlers: %w", jobErr)
		}
		jobRoutes := jobHandlers.Routes

		authRoutes := handlers.Routes
		register = func(mux *http.ServeMux) {
			authRoutes(mux)
			mux.Handle("GET "+EventStreamPath+"{topic...}", streamHandler)
			if nodeRoutes != nil {
				nodeRoutes(mux)
			}
			siteRoutes(mux)
			appRoutes(mux)
			dbRoutes(mux)
			backupRoutes(mux)
			projectRoutes(mux)
			jobRoutes(mux)
		}
		out.SiteRoutesMounted = true
		out.AppRoutesMounted = true
		out.DatabaseRoutesMounted = true
		out.BackupRoutesMounted = true
		out.ProjectRoutesMounted = true
		out.JobRoutesMounted = true
		out.Events = broker
		out.EventStreamMounted = true
		out.NodeRoutesMounted = nodeRoutes != nil
		logger.Info("authentication routes enabled",
			"secret_key_versions", len(cfg.SecretKeys),
			"secure_cookies", cfg.CookieSecure,
			"trusted_origins", len(cfg.TrustedOrigins),
			"node_routes", out.NodeRoutesMounted)
	}

	handler, err := httpserver.New(httpserver.Options{
		Logger:             logger,
		MaxBodyBytes:       cfg.MaxBodyBytes,
		RequestTimeout:     time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
		RegisterRoutes:     register,
		StreamPathPrefixes: []string{EventStreamPath},
	})
	if err != nil {
		return nil, fmt.Errorf("controller: http server: %w", err)
	}
	if sessionLayer != nil {
		handler = sessionLayer(handler)
	}
	out.HTTP = handler
	return out, nil
}
