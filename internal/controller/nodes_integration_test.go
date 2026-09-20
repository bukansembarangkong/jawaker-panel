//go:build integration

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/password"
)

// These tests drive the REAL assembled stack — session middleware, RBAC
// evaluator, node handlers, and a live PostgreSQL — because the properties being
// asserted are about the composition, not about a handler in isolation:
//
//   - every server route is refused without a session;
//   - every server route is refused without the permission, and refused
//     SERVER-SIDE (a hidden button is not a control);
//   - a mutation requiring step-up is refused while unelevated, and accepted
//     once elevated;
//   - a token plaintext is returned exactly once and is unrecoverable after.

// bootstrapOwner creates the platform owner and signs in on THIS harness client.
//
// Signing in on h (rather than returning a separate client) is deliberate: the
// bootstrap endpoint creates the user and its platform_owner binding but no
// session, and later assertions — including the ones that elevate — all run
// through h. Elevating a session that h never established would do nothing.
func (h *harness) bootstrapOwner(t *testing.T) {
	t.Helper()
	const (
		email    = "owner@example.test"
		password = "correct horse battery staple"
	)
	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"`+email+`","display_name":"Owner","password":"`+password+`"}`, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status = %d, want 201", resp.StatusCode)
	}
	h.signIn(t, email, password)
}

// signIn authenticates an existing user on the receiver's client.
func (h *harness) signIn(t *testing.T, email, passwordValue string) {
	t.Helper()
	token, _ := h.csrf()
	body, err := json.Marshal(map[string]string{"email": email, "password": passwordValue})
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	resp := h.csrfPost("/api/v1/auth/login", string(body), token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login as %s status = %d, want 200", email, resp.StatusCode)
	}
}

// elevate drives the REAL step-up endpoint, which is what a successful
// re-authentication produces.
//
// It used to write sessions.elevated_until directly, with a comment claiming the
// elevation mechanism was covered elsewhere. It was not: no endpoint existed, so
// the column was only ever read and every permission the catalog marks as
// requiring step-up was refused forever. A helper that arranges the outcome it
// wants to observe cannot detect that. Going through HTTP is what makes the
// step-up assertions in this file mean anything.
func (h *harness) elevate(t *testing.T) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"password": ownerPassword})
	if err != nil {
		t.Fatalf("marshal elevate: %v", err)
	}
	resp := h.post(t, "/api/v1/auth/elevate", string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("elevate status = %d, want 200", resp.StatusCode)
	}
}

// loginAsWithRole creates a user with the given role binding and signs in as them.
func (h *harness) loginAsWithRole(t *testing.T, email, passwordValue, roleKey, scopeType, scopeID string) *harness {
	t.Helper()
	ctx := context.Background()

	hash, err := password.Hash(passwordValue, *fastParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var userID string
	if err = h.pool.QueryRow(ctx,
		`INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`,
		email, email).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err = h.pool.Exec(ctx,
		`INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)`, userID, hash); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	var roleID string
	if err = h.pool.QueryRow(ctx, `SELECT id FROM roles WHERE key = $1`, roleKey).Scan(&roleID); err != nil {
		t.Fatalf("lookup role %s: %v", roleKey, err)
	}
	if _, err = h.pool.Exec(ctx,
		`INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, $3, $4)`,
		userID, roleID, scopeType, nullUUID(scopeID)); err != nil {
		t.Fatalf("bind role: %v", err)
	}
	// A fresh client, because this user is not the owner and must not inherit
	// the owner's session cookie.
	fresh := h.freshClient()
	token, _ := fresh.csrf()
	body, err := json.Marshal(map[string]string{"email": email, "password": passwordValue})
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	resp := fresh.csrfPost("/api/v1/auth/login", string(body), token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login as %s status = %d, want 200", email, resp.StatusCode)
	}
	return fresh
}

func nullUUID(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// --- unauthenticated ----------------------------------------------------------

// Every server route must refuse an anonymous caller. A route that answered
// without a session would expose the fleet's shape to anyone who can reach the
// controller.
func TestServerRoutesRequireAuth(t *testing.T) {
	h := newHarness(t, nil)

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/servers"},
		{http.MethodGet, "/api/v1/servers/enrollment-tokens"},
		{http.MethodPost, "/api/v1/servers/enrollment-tokens"},
		{http.MethodDelete, "/api/v1/servers/enrollment-tokens/00000000-0000-0000-0000-000000000000"},
		{http.MethodGet, "/api/v1/servers/00000000-0000-0000-0000-000000000000"},
		{http.MethodDelete, "/api/v1/servers/00000000-0000-0000-0000-000000000000"},
	} {
		resp := h.doRaw(tc.method, tc.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// --- deny by default ----------------------------------------------------------

// A user with NO bindings must be refused on every server route. This is the
// deny-by-default property: absence of a grant is a denial, not a default.
func TestServerRoutesDenyUserWithoutBindings(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	fresh := h.loginAsWithRole(t,
		"nobody@example.test", "a sufficiently long password", "viewer", "global", "")

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/servers"},
		{http.MethodGet, "/api/v1/servers/enrollment-tokens"},
		{http.MethodGet, "/api/v1/servers/00000000-0000-0000-0000-000000000000"},
	} {
		resp := fresh.do(tc.method, tc.path, "", nil)
		// The viewer role holds only *.read, so a read of the fleet IS allowed.
		// What must be refused is the enrollment-token listing, which needs
		// server.enroll. Assert per-path rather than blanket-403, so the test
		// states what the role model actually grants.
		if tc.path == "/api/v1/servers/enrollment-tokens" {
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s = %d, want 403 (viewer has no server.enroll)", tc.path, resp.StatusCode)
			}
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("%s = 401, want authenticated access for a viewer", tc.path)
		}
	}

	// A user with no bindings AT ALL is refused everywhere.
	noRoles := h.loginAsWithRole(t,
		"noroles@example.test", "another sufficiently long password", "viewer", "global", "")
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE role_bindings SET revoked_at = now()`); err != nil {
		t.Fatalf("revoke bindings: %v", err)
	}
	for _, path := range []string{"/api/v1/servers", "/api/v1/servers/enrollment-tokens"} {
		resp := noRoles.do(http.MethodGet, path, "", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with no bindings = %d, want 403", path, resp.StatusCode)
		}
	}
}

// A user WITHOUT server.enroll must be refused when minting a token, even though
// they may read the fleet.
func TestEnrollmentTokenCreationRequiresPermission(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	viewer := h.loginAsWithRole(t, "viewer@example.test", "a sufficiently long password", "viewer", "global", "")
	token, _ := viewer.csrf()
	resp := viewer.csrfPost("/api/v1/servers/enrollment-tokens",
		`{"node_name":"sneaky"}`, token)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer minting a token = %d, want 403", resp.StatusCode)
	}
	// And nothing was created.
	var tokens int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens`).Scan(&tokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokens != 0 {
		t.Errorf("%d tokens exist after a denied request, want 0", tokens)
	}
}

// An operator holds network/firewall reads but NOT server.enroll. This asserts a
// role's actual catalog grants rather than a blanket assumption.
func TestOperatorCannotMintToken(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	operator := h.loginAsWithRole(t, "ops@example.test", "a sufficiently long password", "operator", "global", "")
	token, _ := operator.csrf()
	resp := operator.csrfPost("/api/v1/servers/enrollment-tokens", `{"node_name":"ops-node"}`, token)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("operator minting a token = %d, want 403", resp.StatusCode)
	}
}

// --- step-up ------------------------------------------------------------------

// server.enroll requires step-up, so an unelevated owner must be challenged
// rather than allowed. The distinguishing code matters: the UI has to prompt for
// re-authentication, not show "denied".
func TestEnrollmentTokenCreationRequiresStepUp(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/servers/enrollment-tokens", `{"node_name":"step-up-node"}`, token)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unelevated owner minting a token = %d, want 403", resp.StatusCode)
	}
	var envelope struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	decodeBody(t, resp, &envelope)
	if envelope.Error.Code != "step_up_required" {
		t.Errorf("code = %q, want step_up_required", envelope.Error.Code)
	}
	if envelope.Error.Details["step_up"] != true {
		t.Errorf("details = %v, want step_up true", envelope.Error.Details)
	}

	// Nothing was created by the challenged request.
	var tokens int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens`).Scan(&tokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokens != 0 {
		t.Errorf("%d tokens exist after a challenged request, want 0", tokens)
	}
}

// Once elevated the same request succeeds, so the challenge is a gate rather
// than a wall.
func TestEnrollmentTokenCreationSucceedsWhenElevated(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	h.elevate(t)

	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/servers/enrollment-tokens", `{"node_name":"elevated-node"}`, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("elevated owner minting a token = %d, want 201", resp.StatusCode)
	}
	var body struct {
		Token                 string `json:"token"`
		ID                    string `json:"id"`
		NodeName              string `json:"node_name"`
		ControllerFingerprint string `json:"controller_fingerprint"`
	}
	decodeBody(t, resp, &body)
	if !strings.HasPrefix(body.Token, "jwenroll_") {
		t.Errorf("token = %q, want the jwenroll_ prefix", body.Token)
	}
	if body.NodeName != "elevated-node" {
		t.Errorf("node_name = %q, want elevated-node", body.NodeName)
	}
	if body.ControllerFingerprint == "" {
		t.Error("controller_fingerprint is empty; a node cannot pin a root it was not given")
	}
}

// The plaintext must be returned ONCE and be unrecoverable afterwards. This is
// the property that makes the token a one-time credential rather than a
// retrievable password.
func TestTokenPlaintextIsNeverRetrievable(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	h.elevate(t)

	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/servers/enrollment-tokens", `{"node_name":"once-only"}`, token)
	var created struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	decodeBody(t, resp, &created)

	// The list endpoint must not contain the plaintext, in any form.
	listResp := h.do(http.MethodGet, "/api/v1/servers/enrollment-tokens", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listResp.StatusCode)
	}
	raw := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := listResp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}
	if strings.Contains(string(raw), created.Token) {
		t.Error("the list endpoint returned the token plaintext")
	}
	// The digest only, so a database read cannot replay it either.
	var storedPlaintext int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM enrollment_tokens WHERE encode(token_hash, 'escape') = $1`,
		created.Token).Scan(&storedPlaintext); err != nil {
		t.Fatalf("query: %v", err)
	}
	if storedPlaintext != 0 {
		t.Error("the token plaintext is stored in the database")
	}
}

// --- validation ---------------------------------------------------------------

func TestTokenCreationRejectsBadInput(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	h.elevate(t)

	for _, tc := range []struct{ name, body string }{
		{"empty name", `{"node_name":""}`},
		{"name with space", `{"node_name":"has space"}`},
		{"name with slash", `{"node_name":"has/slash"}`},
		{"unknown field", `{"node_name":"ok","run_shell":"id"}`},
		{"malformed json", `{"node_name":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, _ := h.csrf()
			resp := h.csrfPost("/api/v1/servers/enrollment-tokens", tc.body, token)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

// A limit beyond the bound is refused rather than clamped, so a client asking
// for 10000 rows is told no instead of handed a short page.
func TestServerListRejectsUnboundedLimit(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	for _, query := range []string{"?limit=10000", "?limit=0", "?limit=abc", "?offset=-1"} {
		resp := h.do(http.MethodGet, "/api/v1/servers"+query, "", nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET /api/v1/servers%s = %d, want 400", query, resp.StatusCode)
		}
	}
}

// An unknown status filter is a caller error, not an empty page: returning
// nothing for a typo'd filter would look like an empty fleet.
func TestServerListRejectsUnknownFilter(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	resp := h.do(http.MethodGet, "/api/v1/servers?status=exploded", "", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown status filter = %d, want 400", resp.StatusCode)
	}
}

// --- inventory reads ----------------------------------------------------------

// The list is readable by an owner and reports an empty fleet honestly rather
// than omitting fields.
func TestServerListEmptyFleet(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	resp := h.do(http.MethodGet, "/api/v1/servers", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Servers []map[string]any `json:"servers"`
		Total   int              `json:"total"`
		HasMore bool             `json:"has_more"`
	}
	decodeBody(t, resp, &body)
	if len(body.Servers) != 0 || body.Total != 0 {
		t.Errorf("empty fleet reported as %d servers / total %d", len(body.Servers), body.Total)
	}
	if body.HasMore {
		t.Error("has_more is true for an empty fleet")
	}
}

// A server id that does not exist is a 404, and the response must not reveal
// whether a tombstoned row once used that id.
func TestServerDetailNotFound(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	h.elevate(t)

	resp := h.do(http.MethodGet, "/api/v1/servers/00000000-0000-0000-0000-000000000000", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown server = %d, want 404", resp.StatusCode)
	}
}

// --- the enrollment-token route is not shadowed -------------------------------

// "GET /api/v1/servers/enrollment-tokens" must not be routed as
// "GET /api/v1/servers/{id}". If it were, the literal path would be treated as a
// server id and the caller would get a 404 from the wrong handler.
func TestEnrollmentTokenRouteIsNotShadowedByServerID(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	h.elevate(t)

	resp := h.do(http.MethodGet, "/api/v1/servers/enrollment-tokens", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the literal route must win)", resp.StatusCode)
	}
	var body struct {
		Tokens []map[string]any `json:"tokens"`
	}
	decodeBody(t, resp, &body)
	if body.Tokens == nil {
		t.Error("the tokens key is absent; this is the wrong handler")
	}
}
