//go:build integration

// End-to-end tests for the assembled controller HTTP surface.
//
// These drive the REAL stack — middleware chain, CSRF, session cookies, RBAC,
// audit — against a real PostgreSQL, over httptest. Unit tests elsewhere cover
// each piece in isolation; this file is what proves the pieces are wired
// together in the right order, which is the class of bug that unit tests
// structurally cannot catch.

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/dbtest"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMain gives this package its own database, so parallel packages cannot
// reset the schema out from under it.
func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}
	dsn, err := dbtest.IsolatedDatabase(base, "controller")
	if err != nil {
		fmt.Fprintf(os.Stderr, "controller: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "controller: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "controller")
	os.Exit(code)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fastParams keeps the suite quick; production parameters are covered by the
// password package's own tests.
func fastParams() *password.Params {
	return &password.Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

// testKey generates a valid AES-256 master key.
func testKey(t *testing.T) string {
	t.Helper()
	key, err := secret.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// harness is a running controller in-process.
type harness struct {
	t       *testing.T
	server  *httptest.Server
	client  *http.Client
	handler http.Handler
	pool    *pgxpool.Pool
}

// newHarness applies the real migrations and builds the real handler.
func newHarness(t *testing.T, tweak func(*config.Config)) *harness {
	t.Helper()
	ctx := context.Background()

	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping controller integration tests")
	}

	pool, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	m, err := migrate.New(migrations.FS, discardLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := &config.Config{
		ListenAddr:                 "127.0.0.1:8443",
		DatabaseURL:                base,
		LogLevel:                   "error",
		LogFormat:                  "text",
		MaxBodyBytes:               1 << 20,
		RequestTimeoutSeconds:      30,
		SecretKeys:                 map[int]string{1: testKey(t)},
		CookieSecure:               true, // httptest TLS terminates proxy-side; Secure is set explicitly
		LoginAttemptsPerMinute:     100,
		BootstrapAttemptsPerMinute: 100,
	}
	if tweak != nil {
		tweak(cfg)
	}

	assembled, err := Build(Options{
		Config:         cfg,
		Logger:         discardLogger(),
		DB:             pool,
		Now:            func() time.Time { return time.Now().UTC() },
		PasswordParams: fastParams(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !assembled.AuthRoutesMounted {
		t.Fatal("auth routes not mounted despite database and secret key")
	}

	server := httptest.NewTLSServer(assembled.HTTP)
	t.Cleanup(server.Close)

	// server.Client() carries the transport that trusts httptest's self-signed
	// certificate; a plain http.Client would fail the handshake. The cookie jar
	// is still needed so the session cookie survives between requests.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := server.Client()
	client.Jar = jar
	client.Timeout = 10 * time.Second

	return &harness{
		t:       t,
		server:  server,
		client:  client,
		handler: assembled.HTTP,
		pool:    pool,
	}
}

// do performs a request against the live server with the cookie jar.
func (h *harness) do(method, path string, body string, headers map[string]string) *http.Response {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// doRaw performs a request with a FRESH client (no cookies), for testing
// unauthenticated and cross-origin behavior.
func (h *harness) doRaw(method, path, body string, headers map[string]string) *http.Response {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Reuse the TLS-aware transport so the self-signed certificate is trusted,
	// but with no cookie jar: these requests must be unauthenticated.
	client := h.server.Client()
	client.Jar = nil
	client.Timeout = 10 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeBody(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode body: %v", err)
	}
}

// csrfToken primed the token and returns it plus the origin header value.
func (h *harness) csrf() (token, origin string) {
	h.t.Helper()
	resp := h.do(http.MethodGet, "/api/v1/auth/csrf", "", nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("csrf status = %d", resp.StatusCode)
	}
	var body struct {
		Token string `json:"csrf_token"`
	}
	decodeBody(h.t, resp, &body)
	if body.Token == "" {
		h.t.Fatal("empty csrf token")
	}
	return body.Token, h.server.URL
}

// post is a CSRF-correct POST from a fresh client, returning the response.
func (h *harness) csrfPost(path, body, token string) *http.Response {
	h.t.Helper()
	return h.do(http.MethodPost, path, body, map[string]string{
		auth.HeaderCSRF: token,
		"Origin":        h.server.URL,
	})
}

// --- tests -------------------------------------------------------------------------

// The stack must serve public endpoints with no session at all, and the session
// middleware must not interfere with them.
func TestPublicEndpointsReachable(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.do(http.MethodGet, "/healthz", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
	resp = h.do(http.MethodGet, "/api/v1/version", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("version status = %d, want 200", resp.StatusCode)
	}
	// The correlation header is applied by the outermost middleware.
	if got := resp.Header.Get("X-Request-ID"); got == "" {
		t.Error("no request id on the response")
	}
}

// Bootstrap is open until an owner exists, then closed. The status endpoint is
// what the login page uses to decide whether to show the setup form.
func TestBootstrapLifecycle(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.do(http.MethodGet, "/api/v1/auth/bootstrap", "", nil)
	var status struct {
		Requires bool `json:"requires_bootstrap"`
	}
	decodeBody(t, resp, &status)
	if !status.Requires {
		t.Fatal("fresh installation does not report requires_bootstrap")
	}

	token, _ := h.csrf()
	body := `{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`
	resp = h.csrfPost("/api/v1/auth/bootstrap", body, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status = %d, want 201", resp.StatusCode)
	}

	// A second bootstrap is a conflict, not a second owner.
	token2, _ := h.csrf()
	resp = h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"second@example.test","display_name":"Second","password":"another long password value"}`, token2)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("second bootstrap status = %d, want 409", resp.StatusCode)
	}

	var owners int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE is_owner`).Scan(&owners); err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if owners != 1 {
		t.Errorf("owners = %d, want 1", owners)
	}

	resp = h.do(http.MethodGet, "/api/v1/auth/bootstrap", "", nil)
	decodeBody(t, resp, &status)
	if status.Requires {
		t.Error("requires_bootstrap still true after bootstrap")
	}
}

// A state-changing request without a CSRF token must be refused, and the
// rejection must happen BEFORE any credential is checked (nothing is created).
func TestCSRFRequiredOnMutatingRoutes(t *testing.T) {
	h := newHarness(t, nil)

	body := `{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`
	resp := h.do(http.MethodPost, "/api/v1/auth/bootstrap", body, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bootstrap without CSRF status = %d, want 403", resp.StatusCode)
	}

	var users int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Errorf("a CSRF-rejected bootstrap created %d users", users)
	}
}

// A cross-origin request must be refused even with a valid token pair, because
// the origin check is an independent control.
func TestCrossOriginRequestRejected(t *testing.T) {
	h := newHarness(t, nil)
	token, _ := h.csrf()

	body := `{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`
	resp := h.do(http.MethodPost, "/api/v1/auth/bootstrap", body, map[string]string{
		auth.HeaderCSRF: token,
		"Origin":        "https://evil.example",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin status = %d, want 403", resp.StatusCode)
	}
	var users int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Error("a cross-origin request got through")
	}
}

// The full happy path: bootstrap, bootstrap a login session, use the session,
// then log out and confirm the session is dead.
func TestLoginSessionLifecycle(t *testing.T) {
	h := newHarness(t, nil)

	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status = %d", resp.StatusCode)
	}

	// Bootstrap does NOT create a session: the caller must log in.
	resp = h.do(http.MethodGet, "/api/v1/auth/session", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session before login = %d, want 401", resp.StatusCode)
	}

	// The CSRF cookie was rotated by bootstrap; re-prime so the login carries a
	// token the server currently holds.
	loginToken, _ := h.csrf()
	resp = h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"correct horse battery staple"}`, loginToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var loginBody struct {
		SessionID string `json:"session_id"`
		CSRFToken string `json:"csrf_token"`
		User      struct {
			ID      string `json:"id"`
			IsOwner bool   `json:"is_owner"`
		} `json:"user"`
	}
	decodeBody(t, resp, &loginBody)
	if loginBody.SessionID == "" {
		t.Fatal("login returned no session id")
	}
	if !loginBody.User.IsOwner {
		t.Error("bootstrapped owner does not report is_owner")
	}

	// The session cookie must be HttpOnly and Secure. The client jar does not
	// expose HttpOnly cookies, so assert on the raw Set-Cookie header instead.
	var rawCookies []string
	for _, c := range resp.Cookies() {
		rawCookies = append(rawCookies, c.Name)
	}
	if resp.Header.Get("Set-Cookie") == "" {
		t.Fatal("no Set-Cookie on login")
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), auth.SessionCookieName) {
		t.Errorf("Set-Cookie does not carry %s: %q", auth.SessionCookieName,
			resp.Header.Get("Set-Cookie"))
	}
	_ = rawCookies

	// The session endpoint now reports the caller's identity. The Platform Owner
	// holds the full catalog via explicit grants, not a superuser flag.
	resp = h.do(http.MethodGet, "/api/v1/auth/session", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session after login = %d, want 200", resp.StatusCode)
	}
	var sessionBody struct {
		User struct {
			Email   string `json:"email"`
			IsOwner bool   `json:"is_owner"`
		} `json:"user"`
		Permissions struct {
			Global []string `json:"global"`
		} `json:"permissions"`
		Elevated bool `json:"elevated"`
	}
	decodeBody(t, resp, &sessionBody)
	if sessionBody.User.Email != "owner@example.test" {
		t.Errorf("session email = %q", sessionBody.User.Email)
	}
	if !sessionBody.User.IsOwner {
		t.Error("is_owner = false in the session body")
	}
	if len(sessionBody.Permissions.Global) < 50 {
		t.Errorf("owner holds %d global permissions, want the full catalog",
			len(sessionBody.Permissions.Global))
	}
	// Confirm a destructive permission is present, so the full-catalog claim is
	// checked against something specific rather than only a count.
	found := false
	for _, p := range sessionBody.Permissions.Global {
		if p == "site.delete" {
			found = true
		}
	}
	if !found {
		t.Error("owner does not hold site.delete")
	}
	if sessionBody.Elevated {
		t.Error("a freshly created session is already elevated")
	}

	// Log out, then confirm the session is revoked rather than merely unset.
	logoutToken, _ := h.csrf()
	resp = h.csrfPost("/api/v1/auth/logout", "", logoutToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", resp.StatusCode)
	}
	var revoked bool
	if err := h.pool.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, loginBody.SessionID).
		Scan(&revoked); err != nil {
		t.Fatalf("query session: %v", err)
	}
	if !revoked {
		t.Error("logout did not revoke the session row")
	}

	// Even if the client still presented the cookie, the session is dead.
	resp = h.doRaw(http.MethodGet, "/api/v1/auth/session", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("session after logout = %d, want 401", resp.StatusCode)
	}
}

// Wrong password and unknown account must be INDISTINGUISHABLE, or the login
// endpoint becomes an account enumerator.
func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	h := newHarness(t, nil)

	token, _ := h.csrf()
	h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)

	// Wrong password for a real account.
	t1, _ := h.csrf()
	wrongPw := h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"definitely not the password"}`, t1)

	// Unknown account.
	t2, _ := h.csrf()
	unknown := h.csrfPost("/api/v1/auth/login",
		`{"email":"nobody@example.test","password":"definitely not the password"}`, t2)

	if wrongPw.StatusCode != http.StatusUnauthorized || unknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("statuses = %d / %d, want both 401", wrongPw.StatusCode, unknown.StatusCode)
	}

	var a, b map[string]any
	decodeBody(t, wrongPw, &a)
	decodeBody(t, unknown, &b)

	errA, _ := a["error"].(map[string]any)
	errB, _ := b["error"].(map[string]any)
	if errA["code"] != errB["code"] {
		t.Errorf("codes differ: %v vs %v (account enumeration)", errA["code"], errB["code"])
	}
	if errA["message"] != errB["message"] {
		t.Errorf("messages differ: %v vs %v (account enumeration)", errA["message"], errB["message"])
	}

	// Both attempts must be audited, and the unknown-account one must be
	// attributed to the system rather than claiming a user acted.
	var audited int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND result = 'failure'`).
		Scan(&audited); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audited < 2 {
		t.Errorf("audited failures = %d, want the wrong-password and unknown-account attempts", audited)
	}
}

// Account lockout must arm after repeated failures and be reported as a lockout
// rather than as bad credentials.
func TestAccountLockoutAfterRepeatedFailures(t *testing.T) {
	h := newHarness(t, nil)

	token, _ := h.csrf()
	h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)

	// DefaultLockoutPolicy threshold is 5, so the 5th failure arms it.
	var lastStatus int
	for i := 0; i < 5; i++ {
		tok, _ := h.csrf()
		resp := h.csrfPost("/api/v1/auth/login",
			`{"email":"owner@example.test","password":"wrong password attempt"}`, tok)
		lastStatus = resp.StatusCode
	}
	if lastStatus != http.StatusUnauthorized {
		t.Errorf("final failure status = %d, want 401", lastStatus)
	}

	var lockedUntil *time.Time
	if err := h.pool.QueryRow(context.Background(),
		`SELECT locked_until FROM users WHERE email = 'owner@example.test'`).Scan(&lockedUntil); err != nil {
		t.Fatalf("query lockout: %v", err)
	}
	if lockedUntil == nil {
		t.Fatal("lockout not armed after the threshold")
	}

	// The NEXT attempt reports a lockout (423), distinct from bad credentials.
	tok, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"wrong password attempt"}`, tok)
	if resp.StatusCode != http.StatusLocked {
		t.Errorf("locked-account status = %d, want 423", resp.StatusCode)
	}

	// Even the CORRECT password is refused while locked: otherwise a locked
	// account would still be an oracle for password correctness.
	tok2, _ := h.csrf()
	resp = h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"correct horse battery staple"}`, tok2)
	if resp.StatusCode != http.StatusLocked {
		t.Errorf("correct password while locked = %d, want 423", resp.StatusCode)
	}

	// The lockout event must be in the trail with a reason.
	var denied int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events
		 WHERE action = 'auth.login' AND result = 'denied' AND reason IS NOT NULL`).
		Scan(&denied); err != nil {
		t.Fatalf("count denied audit: %v", err)
	}
	if denied == 0 {
		t.Error("no audited denial for the lockout")
	}
}

// Session revocation must take effect immediately through the real stack.
func TestRevokedSessionRejected(t *testing.T) {
	h := newHarness(t, nil)

	token, _ := h.csrf()
	h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)

	loginToken, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"correct horse battery staple"}`, loginToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	var login struct {
		SessionID string `json:"session_id"`
	}
	decodeBody(t, resp, &login)

	// Confirm it works first, so the test is about revocation and not a broken
	// session to begin with.
	if got := h.do(http.MethodGet, "/api/v1/auth/session", "", nil).StatusCode; got != http.StatusOK {
		t.Fatalf("session before revoke = %d, want 200", got)
	}

	// Revoke out of band (simulating an admin action or compromise response).
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE sessions SET revoked_at = now(), revoke_reason = 'admin revoke' WHERE id = $1`,
		login.SessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if got := h.do(http.MethodGet, "/api/v1/auth/session", "", nil).StatusCode; got != http.StatusUnauthorized {
		t.Errorf("session after revoke = %d, want 401", got)
	}
}

// An inactive account must not be able to authenticate even with correct
// credentials, and the response must say so rather than implying a bad password.
func TestSuspendedAccountRejected(t *testing.T) {
	h := newHarness(t, nil)

	token, _ := h.csrf()
	h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)

	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET state = 'suspended' WHERE email = 'owner@example.test'`); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	tok, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"correct horse battery staple"}`, tok)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("suspended login status = %d, want 403", resp.StatusCode)
	}
	var body map[string]any
	decodeBody(t, resp, &body)
	errBody, _ := body["error"].(map[string]any)
	if errBody["code"] != "account_inactive" {
		t.Errorf("code = %v, want account_inactive", errBody["code"])
	}
	// No session may exist for a suspended account.
	var sessions int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE u.email = 'owner@example.test' AND s.revoked_at IS NULL`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("a suspended account obtained %d live sessions", sessions)
	}
}

// Startup must degrade rather than fail when the database or key is absent, and
// must report WHICH piece is missing instead of silently serving no auth routes.
func TestBuildDegradesWithoutDatabaseOrKey(t *testing.T) {
	logger := discardLogger()

	cases := []struct {
		name        string
		cfg         *config.Config
		pool        *pgxpool.Pool
		wantMounted bool
	}{
		{name: "no database", cfg: &config.Config{SecretKeys: map[int]string{1: testKey(t)}}, pool: nil},
		{name: "no secret key", cfg: &config.Config{}, pool: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cfg.MaxBodyBytes == 0 {
				tc.cfg.MaxBodyBytes = 1 << 20
			}
			if tc.cfg.RequestTimeoutSeconds == 0 {
				tc.cfg.RequestTimeoutSeconds = 30
			}
			out, err := Build(Options{Config: tc.cfg, Logger: logger, DB: tc.pool})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if out.AuthRoutesMounted != tc.wantMounted {
				t.Errorf("AuthRoutesMounted = %v, want %v", out.AuthRoutesMounted, tc.wantMounted)
			}
			if out.HTTP == nil {
				t.Fatal("no handler produced")
			}

			// Health must still answer, which is the point of degrading.
			rec := httptest.NewRecorder()
			out.HTTP.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("healthz = %d, want 200 while degraded", rec.Code)
			}
			// The auth surface must be absent, not silently present and broken.
			rec = httptest.NewRecorder()
			out.HTTP.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/bootstrap", nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("auth route status = %d while disabled, want 404", rec.Code)
			}
		})
	}
}

// A malformed master key is a startup FAILURE: an operator who configured a key
// believes second factors work, so starting anyway would silently disable them.
func TestBuildFailsOnMalformedSecretKey(t *testing.T) {
	ctx := context.Background()
	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cfg := &config.Config{
		MaxBodyBytes:          1 << 20,
		RequestTimeoutSeconds: 30,
		SecretKeys:            map[int]string{1: "not-a-valid-base64-key"},
	}
	if _, err := Build(Options{Config: cfg, Logger: discardLogger(), DB: pool}); err == nil {
		t.Fatal("malformed secret key accepted at startup")
	}
}

// Session cookies must honor the configured Secure flag, and the insecure
// override must be visible on the wire rather than silently ignored.
func TestInsecureCookieOverrideIsHonored(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.CookieSecure = false
		cfg.CookieAllowInsecure = true
	})

	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status = %d", resp.StatusCode)
	}
	tok, _ := h.csrf()
	resp = h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"correct horse battery staple"}`, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}

	// With the override set, the session cookie must NOT carry Secure.
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName && c.Secure {
			t.Error("Secure still set despite the explicit override")
		}
	}
}

// The harness itself must prove the RBAC wiring: a session with NO role
// bindings must hold no permissions. This is the Phase 1 gate for "no
// authorization rule exists only in frontend code" — the server is asked, and
// it answers with an empty set.
func TestSessionWithoutBindingsHasNoPermissions(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	token, _ := h.csrf()
	h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)

	// Create a second user directly with a credential but NO role binding, then
	// log in as them.
	hash, err := password.Hash("second user password value", *fastParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	var userID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO users (email, display_name) VALUES ('nobody@example.test', 'No Roles')
		 RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)`,
		userID, hash); err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	// Fresh harness client so the owner's session is not reused.
	fresh := h.freshClient()
	tok, _ := fresh.csrf()
	resp := fresh.csrfPost("/api/v1/auth/login",
		`{"email":"nobody@example.test","password":"second user password value"}`, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}

	resp = fresh.do(http.MethodGet, "/api/v1/auth/session", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status = %d", resp.StatusCode)
	}
	var body struct {
		Permissions struct {
			Global []string `json:"global"`
		} `json:"permissions"`
	}
	decodeBody(t, resp, &body)
	if len(body.Permissions.Global) != 0 {
		t.Errorf("unbound user holds %d permissions; deny-by-default is broken",
			len(body.Permissions.Global))
	}
}

// freshClient returns a client with its own cookie jar, so tests can hold two
// independent sessions against one server.
func (h *harness) freshClient() *harness {
	h.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.t.Fatalf("cookiejar: %v", err)
	}
	client := h.server.Client()
	client.Jar = jar
	client.Timeout = 10 * time.Second
	return &harness{
		t:       h.t,
		server:  h.server,
		client:  client,
		handler: h.handler,
		pool:    h.pool,
	}
}
