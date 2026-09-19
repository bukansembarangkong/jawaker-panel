// Package authsession wires the identity store to HTTP requests: it resolves
// the presented session cookie into a principal, enforces CSRF on
// state-changing requests, and provides the login/logout/bootstrap handlers.
//
// Layering (deliberate, and the reason this is not part of internal/auth):
//
//	internal/auth        transport: cookies, CSRF, principal carrier
//	internal/identity    storage: users, sessions, grants
//	internal/rbac        decision: is this request allowed?
//	internal/authsession wiring: turn a request into a decision input
//
// No authorization rule lives here. A handler asks rbac.Authorize with a
// principal this package constructed; it never decides for itself.
package authsession

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures the session middleware.
type Options struct {
	// DB is the control-plane pool. Required. *pgxpool.Pool satisfies every
	// store interface (Queryer/Execer/Querier), so handlers and the audit
	// writer share one handle.
	DB *pgxpool.Pool
	// Logger receives security-relevant events. Required.
	Logger *slog.Logger
	// Cookies configures the session/CSRF cookie attributes.
	Cookies auth.CookieConfig
	// Policy bounds session lifetime.
	Policy identity.SessionPolicy
	// Secrets opens TOTP shared secrets. Required: without it a second-factor
	// enrollment could not be satisfied, and unwrapping the secret by any other
	// route would bypass the secret subsystem (SECURITY.md §8).
	Secrets *secret.Store
	// Now supplies the clock; zero means time.Now. Injected for tests and so a
	// single request is evaluated against one consistent instant.
	Now func() time.Time
}

func (o Options) validate() error {
	if o.DB == nil {
		return errors.New("authsession: database is required")
	}
	if o.Logger == nil {
		return errors.New("authsession: logger is required")
	}
	return nil
}

// validateHandlers adds the dependencies only the handler set needs. The
// middleware resolves sessions and loads grants but never opens a secret, so it
// does not require the secret store.
func (o Options) validateHandlers() error {
	if err := o.validate(); err != nil {
		return err
	}
	if o.Secrets == nil {
		return errors.New("authsession: secret store is required for authentication handlers")
	}
	return nil
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Middleware resolves the session cookie into a principal when one is present.
//
// It NEVER rejects a request: authentication is required by the route's own
// wrapper (RequireAuth), so public endpoints (login, health) stay reachable.
// A present-but-invalid session is treated as unauthenticated and its cookie is
// cleared, which turns a stale browser into a working login page rather than a
// redirect loop.
func Middleware(opts Options, next http.Handler) http.Handler {
	if err := opts.validate(); err != nil {
		panic(fmt.Sprintf("authsession.Middleware: %v", err))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := auth.SessionTokenFromRequest(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		digest, err := secureid.HashSessionToken(token)
		if err != nil {
			// Forged or truncated cookie: clear it so the browser stops sending
			// it, and continue unauthenticated.
			_ = auth.ClearSessionCookie(w, opts.Cookies)
			next.ServeHTTP(w, r)
			return
		}

		session, user, err := identity.ResolveSession(r.Context(), opts.DB, digest, opts.Policy, opts.now())
		if err != nil {
			// Expected outcomes (expired, revoked, inactive account, unknown
			// token) are all "not authenticated". Only a storage fault deserves
			// a log line at error level.
			if !isExpectedSessionError(err) {
				opts.Logger.ErrorContext(r.Context(), "session resolution failed",
					"error", err, "request_id", httpserver.RequestIDFromRequest(r))
			}
			_ = auth.ClearSessionCookie(w, opts.Cookies)
			next.ServeHTTP(w, r)
			return
		}

		grants, err := identity.LoadGrants(r.Context(), opts.DB, user.ID)
		if err != nil {
			// A session that resolves but cannot load its grants must NOT be
			// treated as authenticated: that would authorize a request with an
			// empty permission set and silently deny everything, hiding a real
			// fault. Fail the request instead.
			opts.Logger.ErrorContext(r.Context(), "grant loading failed",
				"error", err, "user_id", user.ID,
				"request_id", httpserver.RequestIDFromRequest(r))
			httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
			return
		}

		principal := auth.Principal{
			Principal: rbac.Principal{
				UserID:        user.ID,
				Grants:        toRBACGrants(grants),
				ElevatedUntil: session.ElevatedUntil,
				ClientAddr:    parseClientAddr(r),
			},
			SessionID:   session.ID,
			UserID:      user.ID,
			Email:       user.Email,
			DisplayName: user.DisplayName,
			IsOwner:     user.IsOwner,
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

// isExpectedSessionError reports whether a session error is a normal outcome
// rather than a fault worth logging.
func isExpectedSessionError(err error) bool {
	return errors.Is(err, identity.ErrNotFound) ||
		errors.Is(err, identity.ErrSessionExpired) ||
		errors.Is(err, identity.ErrSessionRevoked) ||
		errors.Is(err, identity.ErrUserNotActive)
}

// toRBACGrants converts stored grants into evaluator input, translating the
// stored scope shape and CIDR text. Anything malformed is DROPPED rather than
// coerced: a scope that cannot be parsed must not become a broader one.
func toRBACGrants(grants []identity.Grant) []rbac.Grant {
	out := make([]rbac.Grant, 0, len(grants))
	for _, g := range grants {
		scope, ok := toRBACScope(g.ScopeType, g.ScopeID)
		if !ok {
			continue
		}
		prefixes, err := rbac.ParseCIDRs(g.AllowedCIDRs)
		if err != nil {
			// A grant whose IP restriction cannot be parsed is unusable.
			// Dropping it denies access, which is the safe direction.
			continue
		}
		out = append(out, rbac.Grant{
			Permission:     g.Permission,
			Scope:          scope,
			ExpiresAt:      g.ExpiresAt,
			RevokedAt:      g.RevokedAt,
			AllowedCIDRs:   prefixes,
			RequiresStepUp: g.RequiresStepUp,
		})
	}
	return out
}

func toRBACScope(scopeType, scopeID string) (rbac.Scope, bool) {
	switch rbac.ScopeKind(scopeType) {
	case rbac.ScopeGlobal:
		return rbac.GlobalScope(), true
	case rbac.ScopeServer:
		if scopeID == "" {
			return rbac.Scope{}, false
		}
		return rbac.ServerScope(scopeID), true
	case rbac.ScopeProject:
		if scopeID == "" {
			return rbac.Scope{}, false
		}
		return rbac.ProjectScope(scopeID), true
	case rbac.ScopeResource:
		if scopeID == "" {
			return rbac.Scope{}, false
		}
		return rbac.ResourceScope(scopeID), true
	default:
		return rbac.Scope{}, false
	}
}

// parseClientAddr extracts the client address WITHOUT trusting proxy headers
// (SECURITY.md §10: forwarded headers are not trusted until a trusted-proxy
// policy exists). An unparseable address is returned invalid, which fails an
// IP-restricted grant closed.
func parseClientAddr(r *http.Request) netip.Addr {
	return rbac.ParseAddr(r.RemoteAddr)
}

// RequireAuth rejects unauthenticated requests with the canonical 401 envelope.
// Authentication is a prerequisite; authorization is a separate, explicit step
// so a route can never be "protected" merely by being behind this wrapper.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.PrincipalFrom(r.Context()); !ok {
			httpserver.WriteError(w, r, apierr.Unauthorized(""))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRF enforces the double-submit token and origin check on
// state-changing requests. Applied to every unsafe method; safe methods pass.
func RequireCSRF(csrf *auth.CSRF, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := csrf.Validate(r)
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case errors.Is(err, auth.ErrOriginRejected):
			httpserver.WriteError(w, r, apierr.Forbidden("The request origin is not allowed."))
		default:
			httpserver.WriteError(w, r, apierr.Forbidden("The CSRF token is missing or invalid."))
		}
	})
}

// RequirePermission wraps a handler so the request is authorized before it runs.
//
// This is the ONLY place a decision becomes an HTTP status. Every permission-
// gated endpoint goes through it, which is what makes deny-by-default real: a
// route that forgot it is visible as a route with no permission argument, rather
// than as silently missing logic inside a handler.
//
// The permission and scope are supplied by the ROUTE, never inferred from the
// request body, so a client cannot influence which rule is applied to it.
//
// now passes the injected clock. It is a parameter rather than a direct
// time.Now call so the middleware and the session layer evaluate the same
// instant: near an elevation boundary, two different clocks could authorize a
// request against a different moment than the one that resolved the session.
func RequirePermission(now func() time.Time, permission string, scope rbac.Scope, mutating bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			// Unauthenticated is not the same as unauthorized: 401 tells the
			// client to authenticate rather than that it lacks a permission.
			httpserver.WriteError(w, r, apierr.Unauthorized(""))
			return
		}
		var at time.Time
		if now != nil {
			at = now()
		}
		if apiErr := authorize(principal, rbac.Request{
			Permission: permission,
			Scope:      scope,
			Mutating:   mutating,
			Now:        at,
		}); apiErr != nil {
			httpserver.WriteError(w, r, apiErr)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorize runs the rbac evaluator and converts its decision into an HTTP
// error, so the mapping from decision to status lives in one place.
//
// A step-up denial maps to 403 with a distinguishing code rather than a bare
// refusal, because the UI must prompt for re-authentication, not show "denied".
func authorize(p auth.Principal, req rbac.Request) *apierr.Error {
	decision, err := rbac.Authorize(p.Principal, req)
	if err != nil {
		return apierr.Internal(err)
	}
	if decision.Allowed {
		return nil
	}
	if decision.RequiresStepUp {
		return apierr.StepUpRequired()
	}
	return &apierr.Error{
		Code:    apierr.CodeForbidden,
		Message: "You do not have permission to perform this action.",
		Status:  http.StatusForbidden,
		Details: map[string]any{"reason": decision.Reason},
	}
}

// recordAudit writes an audit event, logging (but not failing the request on) a
// write fault. It is used for events describing something that ALREADY
// succeeded or was refused at the HTTP layer, where there is no surrounding
// transaction to abort. Privileged MUTATIONS must instead pass their own
// transaction to audit.Record so the change and its trail commit together.
func recordAudit(ctx context.Context, logger *slog.Logger, db audit.Execer, reqID string, e audit.Event) {
	e.RequestID = reqID
	if err := audit.Record(ctx, db, e); err != nil {
		logger.ErrorContext(ctx, "audit write failed",
			"error", err, "action", e.Action, "request_id", reqID)
	}
}

// NormalizeEmailForLogin trims an email for lookup. Casing is preserved because
// the column is citext.
func NormalizeEmailForLogin(email string) string { return strings.TrimSpace(email) }
