// Package auth provides browser session transport security: secure cookie
// handling, CSRF protection, and the request-scoped principal.
//
// Scope note: this package owns the TRANSPORT and anti-forgery concerns
// (SECURITY.md §4). The session itself is stored and validated by
// internal/identity, and authorization decisions are made by internal/rbac.
// Keeping those three apart is what stops a rule from ending up in whichever
// layer happened to be convenient.
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
)

// Cookie and header names. These are part of the wire contract with the browser
// and front end, so they are constants rather than configuration.
const (
	// SessionCookieName carries the opaque session token. HttpOnly.
	SessionCookieName = "jawaker_session"
	// CSRFCookieName carries the double-submit token. Deliberately NOT
	// HttpOnly: the front end must read it to echo it back in the header, and
	// that readability is exactly what a cross-origin attacker lacks.
	CSRFCookieName = "jawaker_csrf"
	// HeaderCSRF is where the client echoes the double-submit token.
	HeaderCSRF = "X-CSRF-Token"
)

// CookieConfig describes the session/CSRF cookie attributes.
type CookieConfig struct {
	// Secure requires HTTPS. Defaults to true.
	Secure bool
	// SameSite defaults to Lax: it permits top-level navigation while blocking
	// cross-site form posts, and CSRF tokens plus the origin check cover the
	// remainder.
	SameSite http.SameSite
	// Path scopes the cookie to the whole panel.
	Path string
	// SessionTTL bounds the cookie's Max-Age. It must not exceed the session's
	// absolute timeout, or the browser would keep presenting a token the server
	// has already expired.
	SessionTTL time.Duration
	// CSRFTTL bounds the CSRF cookie.
	CSRFTTL time.Duration
	// AllowInsecure permits Secure=false for local plain-HTTP development.
	// Disabling Secure must be a deliberate, greppable act: without this field a
	// zero-valued config would silently ship session cookies over plain HTTP.
	AllowInsecure bool
}

// DefaultCookieConfig returns the production defaults.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
		Path:       "/",
		SessionTTL: 12 * time.Hour,
		CSRFTTL:    12 * time.Hour,
	}
}

// validate rejects a configuration that would weaken transport security
// silently. Disabling Secure is allowed only through the explicit override, so
// it cannot happen by omission.
func (c CookieConfig) validate() error {
	if !c.Secure && !c.AllowInsecure {
		return errors.New("auth: session cookies must be Secure (set AllowInsecure only for local development)")
	}
	if c.Path == "" {
		return errors.New("auth: cookie path is required")
	}
	if c.SessionTTL <= 0 || c.CSRFTTL <= 0 {
		return errors.New("auth: cookie lifetimes must be positive")
	}
	if c.SameSite == http.SameSiteNoneMode && !c.Secure {
		// Browsers reject SameSite=None without Secure, so this combination is
		// broken as well as unsafe.
		return errors.New("auth: SameSite=None requires Secure")
	}
	return nil
}

// SetSessionCookie writes the session cookie. The token is opaque and its
// digest is what the server stores, so the cookie value alone is useless
// against a database dump.
func SetSessionCookie(w http.ResponseWriter, cfg CookieConfig, token string) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if token == "" {
		return errors.New("auth: session token is required")
	}
	// cfg.validate() rejects Secure=false unless AllowInsecure is set, so the
	// Secure attribute is enforced above; gosec cannot see through it.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure/HttpOnly/SameSite enforced by cfg.validate()
		Name:     SessionCookieName,
		Value:    token,
		Path:     cfg.Path,
		MaxAge:   int(cfg.SessionTTL.Seconds()),
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: cfg.SameSite,
	})
	return nil
}

// ClearSessionCookie expires the session cookie. MaxAge < 0 is how a cookie is
// deleted; omitting MaxAge would leave the cookie in place.
func ClearSessionCookie(w http.ResponseWriter, cfg CookieConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	// Same attributes as the issuing cookie so the browser treats this as the
	// same cookie and removes it.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure/HttpOnly/SameSite enforced by cfg.validate()
		Name:     SessionCookieName,
		Value:    "",
		Path:     cfg.Path,
		MaxAge:   -1,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: cfg.SameSite,
	})
	return nil
}

// SessionTokenFromRequest extracts the presented session token.
//
// A malformed cookie is treated as "no session" rather than an error: the
// cookie is attacker-controllable, and a 400 here would turn a trivially forged
// cookie into a way to probe the login flow.
func SessionTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

// --- CSRF ---------------------------------------------------------------------

// CSRF implements the double-submit cookie pattern plus an origin check.
//
// The pattern works because an attacker on another origin can cause the browser
// to SEND the cookie but cannot READ it, so they cannot produce a matching
// header value. The origin check is a second, independent control: it catches
// the case where the token leaks through some other channel, and it is what
// makes a missing CSRF cookie a hard failure rather than a bypass.
type CSRF struct {
	cfg CookieConfig
	// TrustedOrigins are extra origins accepted for state-changing requests,
	// for a split front end. Empty means same-origin only.
	TrustedOrigins []string
}

// NewCSRF builds a CSRF helper.
func NewCSRF(cfg CookieConfig, trustedOrigins []string) (*CSRF, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	normalized := make([]string, 0, len(trustedOrigins))
	for _, o := range trustedOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("auth: trusted origin %q must be scheme://host", o)
		}
		normalized = append(normalized, strings.ToLower(u.Scheme+"://"+u.Host))
	}
	return &CSRF{cfg: cfg, TrustedOrigins: normalized}, nil
}

// ErrCSRF is returned when a state-changing request fails CSRF validation.
var ErrCSRF = errors.New("auth: CSRF validation failed")

// ErrOriginRejected is returned when the request origin is not allowed.
var ErrOriginRejected = errors.New("auth: request origin is not allowed")

// EnsureToken returns the double-submit token for this request, issuing one if
// the client does not already hold a valid one.
func (c *CSRF) EnsureToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if existing := csrfTokenFromRequest(r); existing != "" {
		return existing, nil
	}
	return c.issueToken(w)
}

// RotateToken always issues a NEW token, invalidating any the client already
// holds.
//
// Call this on authentication. A token minted before login that stays valid
// afterwards is the double-submit analog of session fixation: whatever
// obtained it pre-authentication keeps working post-authentication.
func (c *CSRF) RotateToken(w http.ResponseWriter) (string, error) {
	return c.issueToken(w)
}

// issueToken generates a token and writes the non-HttpOnly cookie the front end
// must be able to read in order to echo it back.
//
// HttpOnly=false is deliberate, not an oversight. The double-submit pattern only
// works because the front end can read this cookie and echo it in a header while
// a cross-origin attacker cannot read it. Making it HttpOnly would defeat the
// scheme. Secure and SameSite are still enforced, so the token is never sent
// over plain HTTP and never attached to a cross-site request.
func (c *CSRF) issueToken(w http.ResponseWriter) (string, error) {
	token, err := secureid.CSRFToken()
	if err != nil {
		return "", err
	}
	// c.cfg.validate() enforces Secure; HttpOnly=false is required by the
	// double-submit pattern documented above.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // CSRF cookie must be readable by the front end; Secure/SameSite enforced by validate()
		Name:     CSRFCookieName,
		Value:    token,
		Path:     c.cfg.Path,
		MaxAge:   int(c.cfg.CSRFTTL.Seconds()),
		Secure:   c.cfg.Secure,
		HttpOnly: false, // must be readable by the front end
		SameSite: c.cfg.SameSite,
	})
	return token, nil
}

// Validate enforces both controls on a state-changing request. It is called for
// every unsafe method; it is a no-op for safe methods, which are exempt by
// definition.
func (c *CSRF) Validate(r *http.Request) error {
	if isSafeMethod(r.Method) {
		return nil
	}
	if err := c.validateOrigin(r); err != nil {
		return err
	}

	cookieToken := csrfTokenFromRequest(r)
	headerToken := strings.TrimSpace(r.Header.Get(HeaderCSRF))
	if cookieToken == "" || headerToken == "" {
		// Fail closed: a missing token is a failure, never a pass. Treating
		// "absent" as "not applicable" is how CSRF checks get bypassed.
		return ErrCSRF
	}
	if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
		return ErrCSRF
	}
	return nil
}

// validateOrigin checks the Origin header against the request host, plus any
// configured trusted origins.
//
// A request with no Origin header is allowed only when it also carries no
// Referer: some non-browser clients legitimately omit both. The token check
// still applies to those requests, so this does not open a hole.
func (c *CSRF) validateOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// Fall back to Referer when Origin is absent (older clients).
		referer := strings.TrimSpace(r.Header.Get("Referer"))
		if referer == "" {
			return nil
		}
		u, err := url.Parse(referer)
		if err != nil {
			return ErrOriginRejected
		}
		origin = u.Scheme + "://" + u.Host
	}

	normalized := strings.ToLower(origin)
	if normalized == "null" {
		// A sandboxed or file:// context. Never a legitimate panel client.
		return ErrOriginRejected
	}
	if normalized == sameOrigin(r) {
		return nil
	}
	for _, trusted := range c.TrustedOrigins {
		if normalized == trusted {
			return nil
		}
	}
	return ErrOriginRejected
}

// sameOrigin derives this request's own origin.
func sameOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.ToLower(scheme + "://" + r.Host)
}

func csrfTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

// isSafeMethod reports whether a method is exempt from CSRF validation by RFC
// 9110: these must not change state, so a cross-site request cannot do harm.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// --- Request principal ---------------------------------------------------------

type principalKey struct{}

// Principal is the authenticated actor for a request. It embeds the rbac
// principal so a handler can pass it straight to Authorize, and it carries the
// identity/session facts the audit trail needs.
type Principal struct {
	rbac.Principal
	// SessionID identifies the session for revocation and device inventory.
	SessionID string
	// UserID is empty for a service or system principal.
	UserID string
	// Email and DisplayName are for display and audit readability only; they
	// never influence an authorization decision.
	Email       string
	DisplayName string
	// IsOwner mirrors the coarse account flag. It is NOT consulted by rbac:
	// the Platform Owner's authority comes from its explicit grants, so this is
	// informational.
	IsOwner bool
}

// WithPrincipal attaches a principal to a context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom retrieves the principal, if the request was authenticated.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// MustPrincipalFrom returns the principal or panics. Use only in handlers that
// cannot run without one because a middleware already rejected unauthenticated
// requests; using it anywhere else would turn a missing auth check into a 500
// instead of a 401.
func MustPrincipalFrom(ctx context.Context) Principal {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		panic("auth: no principal in context; the route is not behind authentication")
	}
	return p
}
