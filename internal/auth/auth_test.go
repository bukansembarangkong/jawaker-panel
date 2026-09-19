package auth

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
)

func testCookies(t *testing.T) CookieConfig {
	t.Helper()
	cfg := DefaultCookieConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("default cookie config invalid: %v", err)
	}
	return cfg
}

// The defaults must be the secure ones: an operator who changes nothing gets
// Secure, HttpOnly, and Lax rather than a permissive cookie.
func TestDefaultCookieConfigIsSecure(t *testing.T) {
	cfg := DefaultCookieConfig()
	if !cfg.Secure {
		t.Error("Secure = false by default")
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cfg.SameSite)
	}
	if cfg.Path != "/" {
		t.Errorf("Path = %q, want /", cfg.Path)
	}
	if cfg.SessionTTL <= 0 || cfg.CSRFTTL <= 0 {
		t.Error("cookie lifetimes must be positive")
	}
}

// A zero-valued config must NOT be accepted: that is exactly the case where a
// session cookie would silently go out over plain HTTP.
func TestZeroCookieConfigRejected(t *testing.T) {
	if err := (CookieConfig{}).validate(); err == nil {
		t.Fatal("zero-valued cookie config accepted")
	}
}

func TestCookieConfigValidation(t *testing.T) {
	base := testCookies(t)

	cases := map[string]func(*CookieConfig){
		"no path":               func(c *CookieConfig) { c.Path = "" },
		"zero session ttl":      func(c *CookieConfig) { c.SessionTTL = 0 },
		"zero csrf ttl":         func(c *CookieConfig) { c.CSRFTTL = 0 },
		"insecure w/o override": func(c *CookieConfig) { c.Secure = false },
		"samesite none insecure": func(c *CookieConfig) {
			c.SameSite = http.SameSiteNoneMode
			c.Secure = false
			c.AllowInsecure = true
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Error("invalid cookie config accepted")
			}
		})
	}

	// Insecure is allowed only with the explicit override.
	cfg := base
	cfg.Secure = false
	cfg.AllowInsecure = true
	if err := cfg.validate(); err != nil {
		t.Errorf("insecure config with the override rejected: %v", err)
	}
}

func TestSetSessionCookieAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := testCookies(t)

	if err := SetSessionCookie(rec, cfg, "session-token"); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies written = %d, want 1", len(cookies))
	}
	c := cookies[0]

	if c.Name != SessionCookieName {
		t.Errorf("name = %q, want %q", c.Name, SessionCookieName)
	}
	if c.Value != "session-token" {
		t.Errorf("value = %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if !c.Secure {
		t.Error("session cookie is not Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge != int(cfg.SessionTTL.Seconds()) {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, int(cfg.SessionTTL.Seconds()))
	}
}

func TestSetSessionCookieRequiresToken(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := SetSessionCookie(rec, testCookies(t), ""); err == nil {
		t.Error("empty token accepted")
	}
}

// A cleared cookie must actually be deleted: MaxAge < 0 is how browsers remove
// a cookie, and omitting it would leave a live session cookie in place.
func TestClearSessionCookieDeletes(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := ClearSessionCookie(rec, testCookies(t)); err != nil {
		t.Fatalf("ClearSessionCookie: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies written = %d, want 1", len(cookies))
	}
	if cookies[0].MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative so the browser deletes it", cookies[0].MaxAge)
	}
	if cookies[0].Value != "" {
		t.Errorf("cleared cookie value = %q, want empty", cookies[0].Value)
	}
}

func TestSessionTokenFromRequest(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if got := SessionTokenFromRequest(r); got != "" {
		t.Errorf("token from a cookieless request = %q, want empty", got)
	}

	reqCookie(r, SessionCookieName, "  tok  ")
	if got := SessionTokenFromRequest(r); got != "tok" {
		t.Errorf("token = %q, want trimmed \"tok\"", got)
	}

	// A cookie with the wrong name must not be accepted.
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	reqCookie(r2, "other", "tok")
	if got := SessionTokenFromRequest(r2); got != "" {
		t.Errorf("token from a misnamed cookie = %q", got)
	}
}

// --- CSRF ------------------------------------------------------------------------

func newCSRF(t *testing.T, trusted ...string) *CSRF {
	t.Helper()
	c, err := NewCSRF(testCookies(t), trusted)
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	return c
}

func TestNewCSRFRejectsBadOrigins(t *testing.T) {
	for _, bad := range []string{"not-a-url", "example.com", "://host", "http://"} {
		if _, err := NewCSRF(testCookies(t), []string{bad}); err == nil {
			t.Errorf("trusted origin %q accepted", bad)
		}
	}
	if _, err := NewCSRF(CookieConfig{}, nil); err == nil {
		t.Error("invalid cookie config accepted")
	}
}

func TestEnsureTokenIssuesThenReuses(t *testing.T) {
	c := newCSRF(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	first, err := c.EnsureToken(rec, r)
	if err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	if first == "" {
		t.Fatal("issued an empty token")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CSRFCookieName {
		t.Fatalf("csrf cookie = %+v", cookies)
	}
	// The front end must be able to read it, so it cannot be HttpOnly.
	if cookies[0].HttpOnly {
		t.Error("CSRF cookie is HttpOnly; the front end could not echo it")
	}
	if !cookies[0].Secure {
		t.Error("CSRF cookie is not Secure")
	}

	// A second call with the token present returns the same value rather than
	// churning the client's token on every request.
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	reqCookie(r2, CSRFCookieName, first)
	again, err := c.EnsureToken(httptest.NewRecorder(), r2)
	if err != nil {
		t.Fatalf("EnsureToken (existing): %v", err)
	}
	if again != first {
		t.Errorf("EnsureToken churned an existing token: %q != %q", again, first)
	}
}

// Rotation on authentication is what prevents a pre-login token from staying
// valid after login, so it must always mint a new value.
func TestRotateTokenAlwaysMintsNew(t *testing.T) {
	c := newCSRF(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	original, err := c.EnsureToken(rec, r)
	if err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	rotated, err := c.RotateToken(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("RotateToken: %v", err)
	}
	if rotated == original {
		t.Error("RotateToken returned the existing token; a pre-login token would survive authentication")
	}
}

// Safe methods are exempt by RFC 9110: they must not change state, so a
// cross-site request cannot do harm.
func TestValidateSkipsSafeMethods(t *testing.T) {
	c := newCSRF(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		r := httptest.NewRequestWithContext(context.Background(), method, "https://panel.test/api", nil)
		if err := c.Validate(r); err != nil {
			t.Errorf("%s should be exempt from CSRF validation: %v", method, err)
		}
	}
}

func TestValidateAcceptsMatchingToken(t *testing.T) {
	c := newCSRF(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "panel.test"
	r.Header.Set("Origin", "https://panel.test")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")

	if err := c.Validate(r); err != nil {
		t.Errorf("matching double-submit rejected: %v", err)
	}
}

// Fail closed: a missing token is a rejection, never a pass. Treating "absent"
// as "not applicable" is how CSRF checks get bypassed.
func TestValidateRejectsMissingToken(t *testing.T) {
	c := newCSRF(t)

	cases := map[string]func(*http.Request){
		"no cookie no header": func(r *http.Request) {},
		"cookie only": func(r *http.Request) {
			reqCookie(r, CSRFCookieName, "tok")
		},
		"header only": func(r *http.Request) {
			r.Header.Set(HeaderCSRF, "tok")
		},
		"mismatch": func(r *http.Request) {
			reqCookie(r, CSRFCookieName, "tok")
			r.Header.Set(HeaderCSRF, "other")
		},
		"empty cookie": func(r *http.Request) {
			reqCookie(r, CSRFCookieName, "  ")
			r.Header.Set(HeaderCSRF, "tok")
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
			r.Host = "panel.test"
			r.Header.Set("Origin", "https://panel.test")
			mutate(r)
			if err := c.Validate(r); err != ErrCSRF {
				t.Errorf("err = %v, want ErrCSRF", err)
			}
		})
	}
}

// The origin check is the independent control: it still rejects a cross-origin
// request even when the attacker somehow obtained a matching token pair.
func TestValidateRejectsCrossOrigin(t *testing.T) {
	c := newCSRF(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "panel.test"
	r.Header.Set("Origin", "https://evil.example")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")

	if err := c.Validate(r); err != ErrOriginRejected {
		t.Errorf("err = %v, want ErrOriginRejected", err)
	}
}

func TestValidateAcceptsTrustedOrigin(t *testing.T) {
	c := newCSRF(t, "https://admin.example")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "panel.test"
	r.Header.Set("Origin", "https://admin.example")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")

	if err := c.Validate(r); err != nil {
		t.Errorf("trusted origin rejected: %v", err)
	}
}

// "null" comes from sandboxed iframes and file:// contexts. It is never a
// legitimate panel client, and treating it as same-origin would defeat the
// check entirely.
func TestValidateRejectsNullOrigin(t *testing.T) {
	c := newCSRF(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "panel.test"
	r.Header.Set("Origin", "null")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")

	if err := c.Validate(r); err != ErrOriginRejected {
		t.Errorf("null origin err = %v, want ErrOriginRejected", err)
	}
}

// A request with no Origin falls back to Referer; both absent is allowed only
// because the token check still applies (non-browser clients legitimately omit
// both, and cannot read the cookie either).
func TestValidateFallsBackToReferer(t *testing.T) {
	c := newCSRF(t)

	// Referer from the same origin: allowed.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "panel.test"
	r.Header.Set("Referer", "https://panel.test/dashboard")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")
	if err := c.Validate(r); err != nil {
		t.Errorf("same-origin referer rejected: %v", err)
	}

	// Referer from another origin: rejected even with matching tokens.
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r2.Host = "panel.test"
	r2.Header.Set("Referer", "https://evil.example/page")
	reqCookie(r2, CSRFCookieName, "tok")
	r2.Header.Set(HeaderCSRF, "tok")
	if err := c.Validate(r2); err != ErrOriginRejected {
		t.Errorf("cross-origin referer err = %v, want ErrOriginRejected", err)
	}

	// An unparseable referer is rejected rather than assumed safe.
	r3 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r3.Host = "panel.test"
	r3.Header.Set("Referer", "\x7f invalid")
	reqCookie(r3, CSRFCookieName, "tok")
	r3.Header.Set(HeaderCSRF, "tok")
	if err := c.Validate(r3); err != ErrOriginRejected {
		t.Errorf("unparseable referer err = %v, want ErrOriginRejected", err)
	}
}

// The origin comparison must be case-insensitive on the scheme and host, or a
// browser that reports "HTTPS://Panel.Test" would be wrongly rejected.
func TestValidateOriginIsCaseInsensitive(t *testing.T) {
	c := newCSRF(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "Panel.Test"
	r.Header.Set("Origin", "HTTPS://panel.TEST")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")

	if err := c.Validate(r); err != nil {
		t.Errorf("case-insensitive origin rejected: %v", err)
	}
}

// A non-TLS request must derive an http origin, otherwise the same-origin check
// would compare against https and either wrongly allow or wrongly reject.
func TestSameOriginReflectsTLS(t *testing.T) {
	plain := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://panel.test/api", nil)
	plain.Host = "panel.test"
	if got := sameOrigin(plain); got != "http://panel.test" {
		t.Errorf("sameOrigin(plain) = %q", got)
	}

	secure := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	secure.Host = "panel.test"
	secure.TLS = &tls.ConnectionState{}
	if got := sameOrigin(secure); got != "https://panel.test" {
		t.Errorf("sameOrigin(tls) = %q", got)
	}
}

// --- principal ---------------------------------------------------------------------

func TestPrincipalRoundTripThroughContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := PrincipalFrom(ctx); ok {
		t.Fatal("empty context reported a principal")
	}

	p := Principal{UserID: "u1", SessionID: "s1", Email: "a@example.test"}
	got, ok := PrincipalFrom(WithPrincipal(ctx, p))
	if !ok {
		t.Fatal("principal not found after attachment")
	}
	if got.UserID != "u1" || got.SessionID != "s1" || got.Email != "a@example.test" {
		t.Errorf("principal = %+v", got)
	}
}

// MustPrincipalFrom is for routes that are guaranteed to sit behind RequireAuth.
// Using it anywhere else would turn a missing auth check into a panic, so the
// panic itself is the assertion.
func TestMustPrincipalFromPanicsWithoutPrincipal(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustPrincipalFrom did not panic on an unauthenticated context")
		}
	}()
	MustPrincipalFrom(context.Background())
}

func TestMustPrincipalFromReturnsPrincipal(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{UserID: "u9"})
	if got := MustPrincipalFrom(ctx); got.UserID != "u9" {
		t.Errorf("principal = %+v", got)
	}
}

// Trusted origins are normalized at construction, so a caller writing
// "HTTP://Admin.Example" gets the same treatment as "http://admin.example".
func TestTrustedOriginsAreNormalized(t *testing.T) {
	c, err := NewCSRF(testCookies(t), []string{"HTTP://Admin.Example", "", "  "})
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	if len(c.TrustedOrigins) != 1 || c.TrustedOrigins[0] != "http://admin.example" {
		t.Errorf("trusted origins = %q, want [http://admin.example]", c.TrustedOrigins)
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
	r.Host = "panel.test"
	r.Header.Set("Origin", "http://admin.example")
	reqCookie(r, CSRFCookieName, "tok")
	r.Header.Set(HeaderCSRF, "tok")
	if err := c.Validate(r); err != nil {
		t.Errorf("normalized trusted origin rejected: %v", err)
	}
}

// Cookie lifetimes must be sane Max-Age values; a fractional second would
// truncate to zero, which browsers treat as a session cookie.
func TestCookieTTLsAreWholeSeconds(t *testing.T) {
	cfg := CookieConfig{Secure: true, Path: "/", SessionTTL: 90 * time.Minute, CSRFTTL: 90 * time.Minute}
	rec := httptest.NewRecorder()
	if err := SetSessionCookie(rec, cfg, "tok"); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}
	got := rec.Result().Cookies()[0].MaxAge
	if got != 5400 {
		t.Errorf("MaxAge = %d, want 5400", got)
	}
}

// The cookie value is URL-safe base64, so it must survive a Set-Cookie round
// trip without needing escaping that would corrupt the token.
func TestSessionCookieValueSurvivesRoundTrip(t *testing.T) {
	// Generated rather than hardcoded: this pins that an ISSUED token survives
	// the cookie round trip, which is the property that matters.
	token, _, err := secureid.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken: %v", err)
	}
	rec := httptest.NewRecorder()
	if cookieErr := SetSessionCookie(rec, testCookies(t), token); cookieErr != nil {
		t.Fatalf("SetSessionCookie: %v", cookieErr)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	if cookies[0].Value != token {
		t.Errorf("round-tripped value = %q, want %q", cookies[0].Value, token)
	}
}

// The trusted-origin list must be validated at construction, not at request
// time, so a typo fails startup rather than silently disabling a cross-origin
// allowance in production.
func TestTrustedOriginValidationHappensAtConstruction(t *testing.T) {
	_, err := NewCSRF(testCookies(t), []string{"https://ok.example", "not a url"})
	if err == nil {
		t.Fatal("bad trusted origin accepted at construction")
	}
	if !strings.Contains(err.Error(), "not a url") {
		t.Errorf("error %q should name the offending origin", err)
	}

	// A well-formed list constructs.
	if _, err := NewCSRF(testCookies(t), []string{"https://a.example", "https://b.example:8443"}); err != nil {
		t.Errorf("valid trusted origins rejected: %v", err)
	}
}

// Origin values that are syntactically odd must not panic or be silently
// accepted. A valid Origin is scheme://host[:port] and never carries a path, so
// anything with a path or query is treated as foreign and rejected fail-closed.
func TestValidateOriginHandlesOddValues(t *testing.T) {
	c := newCSRF(t)
	cases := []struct {
		origin     string
		wantReject bool
	}{
		{"https://panel.test", false},
		{"https://panel.test:8443", true},     // different port is a different origin
		{"http://panel.test/", true},          // wrong scheme and a path
		{"https://panel.test/path?q=1", true}, // a path is not valid in an Origin
	}
	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://panel.test/api", nil)
			r.Host = "panel.test"
			r.Header.Set("Origin", tc.origin)
			reqCookie(r, CSRFCookieName, "tok")
			r.Header.Set(HeaderCSRF, "tok")

			err := c.Validate(r)
			if tc.wantReject && err != ErrOriginRejected {
				t.Errorf("err = %v, want ErrOriginRejected", err)
			}
			if !tc.wantReject && err != nil {
				t.Errorf("unexpected rejection: %v", err)
			}
		})
	}
}

// reqCookie attaches a REQUEST cookie by name/value. It exists so the tests do
// not construct http.Cookie literals inline: a request cookie carries no
// response attributes, and Secure/HttpOnly/SameSite are meaningless on the way
// in, so G124 does not apply here.
func reqCookie(r *http.Request, name, value string) {
	r.AddCookie(&http.Cookie{ //nolint:gosec // request cookie: response attributes do not apply
		Name:  name,
		Value: value,
	})
}
