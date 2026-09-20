//go:build integration

// End-to-end tests for step-up elevation (SECURITY.md §3, §4).
//
// These exist because the elevation mechanism was, until this change, only
// enforced and never obtainable: sessions.elevated_until was read by the RBAC
// evaluator and written by nobody, so every permission the catalog marks as
// requiring step-up was refused forever. The node suite could not catch it
// because its helper wrote the column directly.
//
// The assertions here are therefore about the ENDPOINT, not about the evaluator,
// which already had its own tests.

package controller

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// elevateResponse is the shape POST /api/v1/auth/elevate returns.
type elevateResponse struct {
	Elevated      bool      `json:"elevated"`
	ElevatedUntil time.Time `json:"elevated_until"`
	TTLSeconds    int       `json:"ttl_seconds"`
}

// sessionView is the subset of GET /api/v1/auth/session these tests read.
type sessionView struct {
	SessionID string `json:"session_id"`
	Elevated  bool   `json:"elevated"`
}

// session reads the caller's own session view.
func session(t *testing.T, h *harness) sessionView {
	t.Helper()
	resp := h.do(http.MethodGet, "/api/v1/auth/session", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status = %d, want 200", resp.StatusCode)
	}
	var out sessionView
	decodeBody(t, resp, &out)
	return out
}

// A fresh session starts unelevated, so the challenge the node routes issue is
// the real starting state rather than something a test arranged.
func TestSessionStartsUnelevated(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	if got := session(t, h); got.Elevated {
		t.Error("a freshly created session reports elevated; step-up has no starting state to gate")
	}
}

// The happy path: the password alone elevates an account with no second factor,
// and the change is visible to the session endpoint the UI reads.
func TestElevateSucceedsWithPassword(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	body, err := json.Marshal(map[string]string{"password": ownerPassword})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := h.post(t, "/api/v1/auth/elevate", string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("elevate status = %d, want 200", resp.StatusCode)
	}
	var out elevateResponse
	decodeBody(t, resp, &out)
	if !out.Elevated {
		t.Error("elevate reported success without elevated=true")
	}
	if out.TTLSeconds <= 0 {
		t.Errorf("ttl_seconds = %d, want a positive window", out.TTLSeconds)
	}
	if !out.ElevatedUntil.After(time.Now()) {
		t.Errorf("elevated_until = %s, want a future instant", out.ElevatedUntil)
	}

	if !session(t, h).Elevated {
		t.Error("session endpoint still reports unelevated after a successful step-up")
	}
}

// A wrong password must not elevate. This is the whole point of the endpoint: if
// the session alone were enough, the step-up permissions would be no better
// protected than the ones that need no step-up.
func TestElevateRefusedWithWrongPassword(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	body, err := json.Marshal(map[string]string{"password": "not the owner password"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := h.post(t, "/api/v1/auth/elevate", string(body))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("elevate with a wrong password = %d, want 403", resp.StatusCode)
	}

	if session(t, h).Elevated {
		t.Error("session is elevated after a failed step-up")
	}
}

// An empty password is a caller error, not a credential check that happened to
// fail. Reporting 400 keeps a malformed request distinguishable from a guess.
func TestElevateRequiresAPassword(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	resp := h.post(t, "/api/v1/auth/elevate", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("elevate without a password = %d, want 400", resp.StatusCode)
	}
}

// The endpoint strengthens a session, so it must be behind both CSRF and
// authentication. Without CSRF, a cross-origin page could elevate a session it
// cannot read — and then the stolen cookie would be worth much more.
func TestElevateRequiresCSRF(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	body, err := json.Marshal(map[string]string{"password": ownerPassword})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// h.do sends no CSRF header.
	resp := h.do(http.MethodPost, "/api/v1/auth/elevate", string(body), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("elevate without a CSRF token = %d, want 403", resp.StatusCode)
	}
	if session(t, h).Elevated {
		t.Error("session is elevated without a CSRF token")
	}
}

// An anonymous caller cannot elevate anything.
func TestElevateRequiresAuthentication(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	anon := h.freshClient()
	body, err := json.Marshal(map[string]string{"password": ownerPassword})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	token, _ := anon.csrf()
	resp := anon.csrfPost("/api/v1/auth/elevate", string(body), token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous elevate = %d, want 401", resp.StatusCode)
	}
}

// With a second factor enrolled, the password alone must NOT elevate. Otherwise
// enrolling a factor would make the privileged path CHEAPER than login, which
// inverts what the factor is for.
func TestElevateRequiresSecondFactorWhenEnrolled(t *testing.T) {
	h, clock := setupMFA(t)
	en := enroll(t, h)
	confirm(t, h, clock, en.Secret)

	// The password is correct and there is no code: refused.
	noCode, err := json.Marshal(map[string]string{"password": ownerPassword})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := h.post(t, "/api/v1/auth/elevate", string(noCode))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("elevate without a code on an enrolled account = %d, want 401", resp.StatusCode)
	}

	// A wrong code is refused too.
	wrong, err := json.Marshal(map[string]string{"password": ownerPassword, "totp_code": "000000"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = h.post(t, "/api/v1/auth/elevate", string(wrong))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("elevate with a wrong code = %d, want 401", resp.StatusCode)
	}

	if session(t, h).Elevated {
		t.Fatal("session is elevated without a valid second factor")
	}

	// The correct code elevates. The clock advances first because confirm()
	// already consumed this step, and a replayed step is refused — which would
	// fail this assertion for a reason unrelated to elevation.
	clock.Advance()
	good, err := json.Marshal(map[string]string{
		"password":  ownerPassword,
		"totp_code": clock.Code(t, en.Secret),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = h.post(t, "/api/v1/auth/elevate", string(good))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("elevate with a valid code = %d, want 200", resp.StatusCode)
	}
	if !session(t, h).Elevated {
		t.Error("session is not elevated after a valid password and code")
	}
}

// A recovery code is the fallback for a LOST device at login. Accepting it here
// would let one leaked code elevate any hijacked session, so it is refused.
func TestElevateRefusesRecoveryCode(t *testing.T) {
	h, clock := setupMFA(t)
	en := enroll(t, h)
	conf := confirm(t, h, clock, en.Secret)
	if len(conf.RecoveryCodes) == 0 {
		t.Fatal("confirm returned no recovery codes")
	}
	code := conf.RecoveryCodes[0]

	// The recovery code is NOT a field this endpoint reads, so the request is
	// refused as malformed rather than silently ignored — decodeJSON rejects
	// unknown fields. Either way it must not elevate.
	payload, err := json.Marshal(map[string]string{"password": ownerPassword, "recovery_code": code})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := h.post(t, "/api/v1/auth/elevate", string(payload))
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a recovery code elevated the session")
	}
	if session(t, h).Elevated {
		t.Error("session is elevated after presenting a recovery code")
	}
}

// A requested lifetime beyond the ceiling is refused rather than silently
// clamped, because a caller that asked for an hour and received fifteen minutes
// would believe it holds a window it does not.
func TestElevateRefusesExcessiveLifetime(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	body, err := json.Marshal(map[string]any{
		"password":         ownerPassword,
		"lifetime_seconds": int((2 * time.Hour).Seconds()),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := h.post(t, "/api/v1/auth/elevate", string(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("elevate with an excessive lifetime = %d, want 400", resp.StatusCode)
	}
	if session(t, h).Elevated {
		t.Error("session is elevated despite a refused lifetime")
	}
}

// The elevation is a property of the SESSION row, so ending the session ends it.
// If elevation survived a logout, signing out would not actually return the
// browser to its unprivileged state.
func TestElevationDoesNotSurviveLogout(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	h.elevate(t)

	if !session(t, h).Elevated {
		t.Fatal("precondition: session is not elevated")
	}

	h.endSession(t)
	h.signIn(t, ownerEmail, ownerPassword)

	if session(t, h).Elevated {
		t.Error("a new session reports elevated; elevation leaked across authentication")
	}
}
