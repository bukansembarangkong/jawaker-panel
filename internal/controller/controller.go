// Package controller assembles the control-plane HTTP surface.
//
// It exists so the WIRING is testable. main.go starts a process and cannot be
// imported; if the handler assembly lived there, the composition of session
// middleware, route protection, and the secret subsystem would only ever be
// verified by hand. Putting it here means an integration test can drive the
// exact same stack production runs.
package controller

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/eventstream"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/ratelimit"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
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

		authRoutes := handlers.Routes
		register = func(mux *http.ServeMux) {
			authRoutes(mux)
			mux.Handle("GET "+EventStreamPath+"{topic...}", streamHandler)
		}
		out.Events = broker
		out.EventStreamMounted = true
		logger.Info("authentication routes enabled",
			"secret_key_versions", len(cfg.SecretKeys),
			"secure_cookies", cfg.CookieSecure,
			"trusted_origins", len(cfg.TrustedOrigins))
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
