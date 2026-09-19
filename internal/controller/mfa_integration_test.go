//go:build integration

// End-to-end tests for the second-factor HTTP surface: enroll, confirm, login
// with a TOTP code and with a recovery code, and disable. These drive the REAL
// assembled controller (session cookies, CSRF, RBAC, audit) over httptest.
//
// TOTP codes are accepted at most once per time step, so every step of a test
// advances an injected clock by one step. Two steps at once would exceed the
// Ã‚Â±1 skew the server allows; one step is the smallest change that makes the
// previous code unusable, which is what these tests need.

package controller

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/totp"
)

const ownerEmail = "owner@example.test"
const ownerPassword = "correct horse battery staple"

// stepDuration is the RFC 6238 time step, in seconds.
const stepDuration = int64(totp.DefaultPeriod)

// mfaClock is a wall clock advanced in whole TOTP steps by the test.
//
// It is stored as an atomic counter because the server reads it from request
// goroutines while the test advances it from the test goroutine.
type mfaClock struct {
	base  time.Time
	steps atomic.Int64
}

func newMFAClock() *mfaClock {
	// Aligned to a step boundary so the first code is never about to expire
	// mid-assertion, which would make the suite flaky for a reason unrelated to
	// what it checks.
	base := time.Unix((time.Now().UTC().Unix()/stepDuration)*stepDuration, 0).UTC()
	return &mfaClock{base: base}
}

func (c *mfaClock) Now() time.Time {
	return c.base.Add(time.Duration(c.steps.Load()) * time.Duration(stepDuration) * time.Second)
}

// Advance moves the clock forward one time step, making the code the test last
// used invalid by expiry rather than by consumption.
func (c *mfaClock) Advance() {
	c.steps.Add(1)
}

// Code returns a valid code for the secret at the clock's current step.
func (c *mfaClock) Code(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.Code(secret, totp.StepFor(c.Now(), totp.DefaultConfig()), totp.DefaultConfig())
	if err != nil {
		t.Fatalf("totp.Code: %v", err)
	}
	return code
}

// setupMFA brings up a harness with a controllable clock and an authenticated
// owner session.
func setupMFA(t *testing.T) (*harness, *mfaClock) {
	t.Helper()
	clock := newMFAClock()
	h := newHarnessAt(t, nil, clock.Now)
	bootstrapOwner(t, h)
	loginOwner(t, h)
	return h, clock
}

// post sends a CSRF-correct POST, priming the token immediately beforehand.
//
// Login ROTATES the CSRF token, so a token obtained before a login is invalid
// afterwards. Priming per request is the only way the test cannot fail for a
// reason unrelated to what it is checking.
func (h *harness) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	token, _ := h.csrf()
	return h.csrfPost(path, body, token)
}

// login posts the login form.
func (h *harness) login(t *testing.T, body string) *http.Response {
	t.Helper()
	return h.post(t, "/api/v1/auth/login", body)
}

// endSession makes sure no session is live before the next login.
//
// A login attempt that failed did not mint a session, and a previous logout
// already ended the one before it, so the honest thing to do here is tolerate
// both outcomes: 200 means a session was ended, 401 means there was none. Any
// other status is a real problem and fails the test.
func (h *harness) endSession(t *testing.T) {
	t.Helper()
	switch r := h.post(t, "/api/v1/auth/logout", ""); r.StatusCode {
	case http.StatusOK, http.StatusUnauthorized:
	default:
		t.Fatalf("logout status = %d, want 200 or 401", r.StatusCode)
	}
}

// enrollResponse is the shape handleTOTPEnroll returns.
type enrollResponse struct {
	EnrollmentID string `json:"enrollment_id"`
	Secret       string `json:"secret"`
	OTPAuthURI   string `json:"otpauth_uri"`
	Algorithm    string `json:"algorithm"`
	Digits       int    `json:"digits"`
	PeriodSec    int    `json:"period_seconds"`
}

// confirmResponse is the shape handleTOTPConfirm returns.
type confirmResponse struct {
	Status        string   `json:"status"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// mfaStatus is the shape handleMFAStatus returns.
type mfaStatus struct {
	Enrolled  bool `json:"totp_enrolled"`
	Pending   bool `json:"totp_enrollment_pending"`
	Remaining int  `json:"recovery_codes_remaining"`
}

// errorEnvelope is the API.md Ã‚Â§8 error shape, for asserting stable codes.
type errorEnvelope struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// jsonStr renders a Go string as a JSON string literal, so a test body cannot be
// broken by a quote or backslash in a value.
func jsonStr(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// loginBody builds a login request body.
func loginBody(fields map[string]string) string {
	var sb strings.Builder
	sb.WriteString("{")
	first := true
	for _, k := range []string{"email", "password", "totp_code", "recovery_code"} {
		v, ok := fields[k]
		if !ok {
			continue
		}
		if !first {
			sb.WriteString(",")
		}
		first = false
		sb.WriteString(jsonStr(k))
		sb.WriteString(":")
		sb.WriteString(jsonStr(v))
	}
	sb.WriteString("}")
	return sb.String()
}

// enroll runs the enroll step and asserts the response carries usable material.
func enroll(t *testing.T, h *harness) enrollResponse {
	t.Helper()
	resp := h.post(t, "/api/v1/auth/mfa/totp/enroll", `{"password":`+jsonStr(ownerPassword)+`}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", resp.StatusCode)
	}
	var out enrollResponse
	decodeBody(t, resp, &out)
	if out.Secret == "" {
		t.Fatal("enroll returned no secret")
	}
	if out.EnrollmentID == "" {
		t.Fatal("enroll returned no enrollment id")
	}
	if !strings.HasPrefix(out.OTPAuthURI, "otpauth://totp/") {
		t.Errorf("otpauth_uri = %q, want an otpauth URI", out.OTPAuthURI)
	}
	if !strings.Contains(out.OTPAuthURI, "issuer=JAWAKER") {
		t.Errorf("otpauth_uri = %q, want the issuer labelled", out.OTPAuthURI)
	}
	if !strings.Contains(out.OTPAuthURI, "secret="+out.Secret) {
		t.Error("otpauth_uri does not carry the enrolled secret")
	}
	return out
}

// confirm confirms the pending enrollment with a code for the current step.
func confirm(t *testing.T, h *harness, clock *mfaClock, secret string) confirmResponse {
	t.Helper()
	resp := h.post(t, "/api/v1/auth/mfa/totp/confirm", `{"code":`+jsonStr(clock.Code(t, secret))+`}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm status = %d, want 200", resp.StatusCode)
	}
	var out confirmResponse
	decodeBody(t, resp, &out)
	return out
}

// status reads the caller's MFA state.
func status(t *testing.T, h *harness) mfaStatus {
	t.Helper()
	resp := h.do(http.MethodGet, "/api/v1/auth/mfa", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa status = %d, want 200", resp.StatusCode)
	}
	var out mfaStatus
	decodeBody(t, resp, &out)
	return out
}

// The happy path end to end: enroll, confirm, then a second factor is required
// at login and a code satisfies it.
func TestMFAEnrollConfirmAndLogin(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	conf := confirm(t, h, clock, en.Secret)
	if conf.Status != "enabled" {
		t.Errorf("confirm status = %q, want enabled", conf.Status)
	}
	if len(conf.RecoveryCodes) == 0 {
		t.Fatal("confirm returned no recovery codes")
	}

	st := status(t, h)
	if !st.Enrolled || st.Pending {
		t.Errorf("status = %+v, want enrolled and not pending", st)
	}
	if st.Remaining != len(conf.RecoveryCodes) {
		t.Errorf("recovery_codes_remaining = %d, want %d", st.Remaining, len(conf.RecoveryCodes))
	}

	// A fresh session must be earned with BOTH factors from now on.
	h.endSession(t)

	// Password alone is refused, with a stable code the UI can branch on.
	r := h.login(t, loginBody(map[string]string{"email": ownerEmail, "password": ownerPassword}))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password-only login = %d, want 401", r.StatusCode)
	}
	var env errorEnvelope
	decodeBody(t, r, &env)
	if env.Error.Code != authsession.CodeTOTPRequired {
		t.Errorf("code = %q, want %q", env.Error.Code, authsession.CodeTOTPRequired)
	}

	// Password plus a current code succeeds. The clock advances one step because
	// the confirmation above consumed the code for the current one.
	clock.Advance()
	r = h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "totp_code": clock.Code(t, en.Secret),
	}))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login with TOTP = %d, want 200", r.StatusCode)
	}
}

// The TOTP code that confirmed the enrollment cannot be replayed at login, even
// inside its own time window: the step was consumed by the confirmation.
func TestMFAConfirmingCodeCannotBeReplayed(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	code := clock.Code(t, en.Secret)
	step := totp.StepFor(clock.Now(), totp.DefaultConfig())
	if r := h.post(t, "/api/v1/auth/mfa/totp/confirm", `{"code":`+jsonStr(code)+`}`); r.StatusCode != http.StatusOK {
		t.Fatalf("confirm status = %d, want 200", r.StatusCode)
	}

	h.endSession(t)

	// The clock has NOT moved: this is a replay within the same window, which is
	// exactly the attack an observed code enables.
	r := h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "totp_code": code,
	}))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login replaying the confirmation code = %d, want 401 (step %d was consumed)", r.StatusCode, step)
	}
	var env errorEnvelope
	decodeBody(t, r, &env)
	if env.Error.Code != authsession.CodeTOTPInvalid {
		t.Errorf("code = %q, want %q", env.Error.Code, authsession.CodeTOTPInvalid)
	}
}

// A recovery code is a single-use bypass for the second factor.
func TestMFARecoveryCodeLogin(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	conf := confirm(t, h, clock, en.Secret)

	h.endSession(t)
	withRecovery := loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "recovery_code": conf.RecoveryCodes[0],
	})
	if r := h.login(t, withRecovery); r.StatusCode != http.StatusOK {
		t.Fatalf("login with recovery code = %d, want 200", r.StatusCode)
	}

	// The same code is spent.
	h.endSession(t)
	if r := h.login(t, withRecovery); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused recovery code login = %d, want 401", r.StatusCode)
	}

	// An invented code is refused with the same envelope as a wrong TOTP code, so
	// the response does not reveal which credential class was closer. No session
	// exists at this point â€” the logout above ended it and the failed login
	// minted none â€” so this request is simply unauthenticated.
	bogus := loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "recovery_code": "zzzz-zzzz-zzzz",
	})
	r := h.login(t, bogus)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with a bogus recovery code = %d, want 401", r.StatusCode)
	}
	var env errorEnvelope
	decodeBody(t, r, &env)
	if env.Error.Code != authsession.CodeTOTPInvalid {
		t.Errorf("code = %q, want %q", env.Error.Code, authsession.CodeTOTPInvalid)
	}
}

// A recovery code works however it was transcribed: the user is reading it off
// paper and must not be locked out by casing or separators.
func TestMFARecoveryCodeAcceptsTranscription(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	conf := confirm(t, h, clock, en.Secret)
	if len(conf.RecoveryCodes) < 2 {
		t.Fatalf("confirm returned %d codes, want at least 2", len(conf.RecoveryCodes))
	}
	variant := strings.ToUpper(strings.ReplaceAll(conf.RecoveryCodes[1], "-", " "))

	h.endSession(t)
	r := h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "recovery_code": variant,
	}))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login with transcribed code %q = %d, want 200", variant, r.StatusCode)
	}
}

// Enrolling requires the current password. A session cookie proves the caller
// once authenticated, not that they are still the person at the keyboard.
func TestMFAEnrollRequiresPassword(t *testing.T) {
	h, _ := setupMFA(t)

	r := h.post(t, "/api/v1/auth/mfa/totp/enroll", `{}`)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("enroll without password = %d, want 400", r.StatusCode)
	}

	r = h.post(t, "/api/v1/auth/mfa/totp/enroll", `{"password":"wrong password entirely"}`)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("enroll with wrong password = %d, want 403", r.StatusCode)
	}

	// Nothing was enrolled by the refused attempts.
	st := status(t, h)
	if st.Enrolled || st.Pending {
		t.Errorf("status = %+v, want nothing enrolled after refused attempts", st)
	}

	// The refusal is audited, so a burst of attempts on one account is visible.
	var denied int
	if err := h.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE action = 'mfa.totp.enroll' AND result = 'denied'`).Scan(&denied); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if denied != 1 {
		t.Errorf("denied enroll audit rows = %d, want 1 (the wrong password)", denied)
	}
}

// Enrollment must NOT disturb a factor already in force.
//
// This is the HTTP-level proof of the downgrade regression: an attacker holding
// a session could call enroll and then stop, and the account would have no
// second factor at the next login.
func TestMFAEnrollKeepsActiveFactor(t *testing.T) {
	h, clock := setupMFA(t)

	first := enroll(t, h)
	confirm(t, h, clock, first.Secret)

	// Enroll a replacement and deliberately do NOT confirm it.
	second := enroll(t, h)
	if second.EnrollmentID == first.EnrollmentID {
		t.Fatal("the replacement reused the first enrollment's id")
	}
	if second.Secret == first.Secret {
		t.Error("the replacement reused the first enrollment's secret")
	}

	st := status(t, h)
	if !st.Enrolled || !st.Pending {
		t.Errorf("status = %+v, want the old factor enrolled and the new one pending", st)
	}

	h.endSession(t)
	clock.Advance()
	r := h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "totp_code": clock.Code(t, first.Secret),
	}))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login with the original factor = %d, want 200 (enrolling a replacement must not disarm the account)", r.StatusCode)
	}

	// The unconfirmed replacement's secret is not yet a valid factor.
	h.endSession(t)
	clock.Advance()
	r = h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "totp_code": clock.Code(t, second.Secret),
	}))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with an unconfirmed enrollment's code = %d, want 401", r.StatusCode)
	}
}

// Confirming the replacement promotes it, and the original factor stops working.
func TestMFAConfirmReplacementSwapsFactor(t *testing.T) {
	h, clock := setupMFA(t)

	first := enroll(t, h)
	confirm(t, h, clock, first.Secret)
	second := enroll(t, h)
	clock.Advance()
	confirm(t, h, clock, second.Secret)

	st := status(t, h)
	if !st.Enrolled || st.Pending {
		t.Errorf("status = %+v, want the replacement confirmed and nothing pending", st)
	}

	h.endSession(t)
	clock.Advance()
	r := h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "totp_code": clock.Code(t, first.Secret),
	}))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with the superseded factor = %d, want 401", r.StatusCode)
	}

	h.endSession(t)
	clock.Advance()
	r = h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "totp_code": clock.Code(t, second.Secret),
	}))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login with the replacement = %d, want 200", r.StatusCode)
	}
}

// Confirming with a wrong code is refused and does not enable the factor.
func TestMFAConfirmRejectsWrongCode(t *testing.T) {
	h, _ := setupMFA(t)
	enroll(t, h)

	r := h.post(t, "/api/v1/auth/mfa/totp/confirm", `{"code":"000000"}`)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("confirm with wrong code = %d, want 401", r.StatusCode)
	}
	var env errorEnvelope
	decodeBody(t, r, &env)
	if env.Error.Code != authsession.CodeTOTPInvalid {
		t.Errorf("code = %q, want %q", env.Error.Code, authsession.CodeTOTPInvalid)
	}

	st := status(t, h)
	if st.Enrolled {
		t.Error("a wrong code enabled the factor")
	}
	if !st.Pending {
		t.Error("a refused confirmation abandoned the pending enrollment; the user would have to re-scan")
	}
}

// A confirm request with no code is a malformed request, not an authentication
// failure.
func TestMFAConfirmRequiresACode(t *testing.T) {
	h, _ := setupMFA(t)
	enroll(t, h)

	r := h.post(t, "/api/v1/auth/mfa/totp/confirm", `{}`)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("confirm without a code = %d, want 400", r.StatusCode)
	}
}

// Confirming with nothing pending reports not-found, so a client cannot believe
// it enabled a factor it never enrolled.
func TestMFAConfirmWithoutPendingIsNotFound(t *testing.T) {
	h, _ := setupMFA(t)

	r := h.post(t, "/api/v1/auth/mfa/totp/confirm", `{"code":"123456"}`)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("confirm without pending = %d, want 404", r.StatusCode)
	}
}

// Disabling requires the password AND a reason, revokes the recovery codes, and
// ends every session.
func TestMFADisableRevokesAndRequiresReason(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	conf := confirm(t, h, clock, en.Secret)
	if len(conf.RecoveryCodes) == 0 {
		t.Fatal("confirm returned no recovery codes")
	}

	r := h.post(t, "/api/v1/auth/mfa/totp/disable", `{"password":`+jsonStr(ownerPassword)+`}`)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("disable without a reason = %d, want 400", r.StatusCode)
	}

	r = h.post(t, "/api/v1/auth/mfa/totp/disable", `{"reason":"lost device"}`)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("disable without the password = %d, want 400", r.StatusCode)
	}

	r = h.post(t, "/api/v1/auth/mfa/totp/disable",
		`{"password":`+jsonStr(ownerPassword)+`,"reason":"lost device"}`)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("disable = %d, want 200", r.StatusCode)
	}
	var disabled struct {
		Status       string `json:"status"`
		CodesRevoked int    `json:"recovery_codes_revoked"`
		Sessions     int    `json:"sessions_revoked"`
	}
	decodeBody(t, r, &disabled)
	if disabled.Status != "disabled" {
		t.Errorf("status = %q, want disabled", disabled.Status)
	}
	if disabled.CodesRevoked != len(conf.RecoveryCodes) {
		t.Errorf("recovery_codes_revoked = %d, want %d", disabled.CodesRevoked, len(conf.RecoveryCodes))
	}
	if disabled.Sessions == 0 {
		t.Error("disable reported no sessions revoked")
	}

	// The caller's own session is gone, which is the point: a hijacked session
	// cannot disable MFA and then keep using that same session.
	if r := h.do(http.MethodGet, "/api/v1/auth/mfa", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("MFA status after disable = %d, want 401 (every session was revoked)", r.StatusCode)
	}

	// The reason reached the audit trail: an unexplained vanished second factor
	// is the signal an incident reviewer looks for.
	var audited int
	if err := h.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE action = 'mfa.totp.disable' AND result = 'success' AND reason = 'lost device'`,
	).Scan(&audited); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if audited != 1 {
		t.Errorf("audited disable rows with the reason = %d, want 1", audited)
	}

	// Login now needs only the password. The previous session was revoked, so the
	// cookie in the jar is dead and this login mints a new one.
	if r := h.login(t, loginBody(map[string]string{"email": ownerEmail, "password": ownerPassword})); r.StatusCode != http.StatusOK {
		t.Fatalf("login after disable = %d, want 200", r.StatusCode)
	}
}

// A recovery code from before the disable is dead afterwards: the codes bypass a
// factor that no longer exists.
func TestMFADisableKillsRecoveryCodes(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	conf := confirm(t, h, clock, en.Secret)

	if r := h.post(t, "/api/v1/auth/mfa/totp/disable",
		`{"password":`+jsonStr(ownerPassword)+`,"reason":"rotating device"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("disable = %d, want 200", r.StatusCode)
	}

	r := h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "recovery_code": conf.RecoveryCodes[0],
	}))
	// The account no longer HAS a second factor, so the login is a plain
	// password login and succeeds Ã¢â‚¬â€ but the code was not what admitted it.
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login after disable = %d, want 200", r.StatusCode)
	}
	var remaining int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM recovery_codes WHERE used_at IS NULL`).Scan(&remaining); err != nil {
		t.Fatalf("count codes: %v", err)
	}
	if remaining != 0 {
		t.Errorf("unused recovery codes after disable = %d, want 0", remaining)
	}
}

// Disabling when nothing is enrolled reports not-found rather than succeeding.
func TestMFADisableWithoutFactorIsNotFound(t *testing.T) {
	h, _ := setupMFA(t)

	r := h.post(t, "/api/v1/auth/mfa/totp/disable",
		`{"password":`+jsonStr(ownerPassword)+`,"reason":"nothing to disable"}`)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("disable without a factor = %d, want 404", r.StatusCode)
	}
}

// Regenerating recovery codes requires the password and, when a factor is in
// force, a current code: a password alone must not mint a permanent bypass.
func TestMFARecoveryRegenerateRequiresTOTP(t *testing.T) {
	h, clock := setupMFA(t)

	en := enroll(t, h)
	first := confirm(t, h, clock, en.Secret)

	r := h.post(t, "/api/v1/auth/mfa/recovery-codes", `{"password":`+jsonStr(ownerPassword)+`}`)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("regenerate without a TOTP code = %d, want 401", r.StatusCode)
	}
	var env errorEnvelope
	decodeBody(t, r, &env)
	if env.Error.Code != authsession.CodeTOTPRequired {
		t.Errorf("code = %q, want %q", env.Error.Code, authsession.CodeTOTPRequired)
	}

	// A wrong code is refused and does not rotate the set.
	clock.Advance()
	r = h.post(t, "/api/v1/auth/mfa/recovery-codes",
		`{"password":`+jsonStr(ownerPassword)+`,"code":"000000"}`)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("regenerate with a wrong code = %d, want 401", r.StatusCode)
	}
	st := status(t, h)
	if st.Remaining != len(first.RecoveryCodes) {
		t.Errorf("remaining = %d, want %d (a refused rotation must not change the set)", st.Remaining, len(first.RecoveryCodes))
	}

	// A valid code rotates the set.
	clock.Advance()
	r = h.post(t, "/api/v1/auth/mfa/recovery-codes",
		`{"password":`+jsonStr(ownerPassword)+`,"code":`+jsonStr(clock.Code(t, en.Secret))+`}`)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("regenerate with a TOTP code = %d, want 200", r.StatusCode)
	}
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	decodeBody(t, r, &out)
	if len(out.RecoveryCodes) == 0 {
		t.Fatal("regenerate returned no codes")
	}
	if len(out.RecoveryCodes) != len(first.RecoveryCodes) {
		t.Errorf("regenerate returned %d codes, want %d", len(out.RecoveryCodes), len(first.RecoveryCodes))
	}

	st = status(t, h)
	if st.Remaining != len(out.RecoveryCodes) {
		t.Errorf("recovery_codes_remaining = %d, want %d (the previous set was replaced)", st.Remaining, len(out.RecoveryCodes))
	}

	// A code from the superseded set is dead, so a code on a lost note stops
	// working the moment the user rotates.
	h.endSession(t)
	r = h.login(t, loginBody(map[string]string{
		"email": ownerEmail, "password": ownerPassword, "recovery_code": first.RecoveryCodes[0],
	}))
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("login with a superseded recovery code = %d, want 401", r.StatusCode)
	}
}

// With no factor enrolled, regeneration needs only the password: there is no
// code to present, and refusing would make the codes unreachable.
func TestMFARecoveryRegenerateWithoutFactorNeedsPasswordOnly(t *testing.T) {
	h, _ := setupMFA(t)

	r := h.post(t, "/api/v1/auth/mfa/recovery-codes", `{}`)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("regenerate without a password = %d, want 400", r.StatusCode)
	}

	r = h.post(t, "/api/v1/auth/mfa/recovery-codes", `{"password":`+jsonStr(ownerPassword)+`}`)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("regenerate with only a password = %d, want 200", r.StatusCode)
	}
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	decodeBody(t, r, &out)
	if len(out.RecoveryCodes) == 0 {
		t.Error("regenerate returned no codes")
	}
	for _, code := range out.RecoveryCodes {
		if !strings.Contains(code, "-") {
			t.Errorf("recovery code %q is not grouped for transcription", code)
		}
	}
}

// Every MFA route is authenticated. An unauthenticated client learns nothing
// about the account's second-factor state.
func TestMFARoutesRequireAuth(t *testing.T) {
	h := newHarness(t, nil)
	bootstrapOwner(t, h)

	if r := h.doRaw(http.MethodGet, "/api/v1/auth/mfa", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated MFA status = %d, want 401", r.StatusCode)
	}
	for _, path := range []string{
		"/api/v1/auth/mfa/totp/enroll",
		"/api/v1/auth/mfa/totp/confirm",
		"/api/v1/auth/mfa/totp/disable",
		"/api/v1/auth/mfa/recovery-codes",
	} {
		r := h.doRaw(http.MethodPost, path, `{"password":"x"}`, map[string]string{
			"Content-Type": "application/json",
		})
		// 401 (no session) or 403 (CSRF) Ã¢â‚¬â€ never 200.
		if r.StatusCode == http.StatusOK {
			t.Errorf("unauthenticated POST %s succeeded", path)
		}
	}
}

// A state-changing MFA request without a CSRF token is refused even with a valid
// session: cookie-authenticated mutations are exactly what CSRF protects.
func TestMFAMutationsRequireCSRF(t *testing.T) {
	h, _ := setupMFA(t)

	r := h.do(http.MethodPost, "/api/v1/auth/mfa/totp/enroll",
		`{"password":`+jsonStr(ownerPassword)+`}`, map[string]string{
			"Content-Type": "application/json",
		})
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("enroll without CSRF = %d, want 403", r.StatusCode)
	}

	// Nothing was enrolled by the refused request.
	if st := status(t, h); st.Pending || st.Enrolled {
		t.Errorf("status = %+v, want nothing enrolled after a refused request", st)
	}
}

// An unknown field in the request body is rejected rather than ignored, so a
// typo in a security-relevant request is visible instead of silently dropping a
// setting the caller believed they sent.
func TestMFARejectsUnknownFields(t *testing.T) {
	h, _ := setupMFA(t)

	r := h.post(t, "/api/v1/auth/mfa/totp/enroll",
		`{"password":`+jsonStr(ownerPassword)+`,"totally_bogus":1}`)
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("enroll with an unknown field = %d, want 400", r.StatusCode)
	}
	if st := status(t, h); st.Pending || st.Enrolled {
		t.Errorf("status = %+v, want nothing enrolled after a malformed request", st)
	}
}

// The provisioning URI must not carry the secret anywhere it could be logged,
// and the response must not repeat the secret under a second key.
func TestMFAEnrollResponseDoesNotLeakBeyondTheSecretField(t *testing.T) {
	h, _ := setupMFA(t)

	resp := h.post(t, "/api/v1/auth/mfa/totp/enroll", `{"password":`+jsonStr(ownerPassword)+`}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", resp.StatusCode)
	}
	var raw map[string]json.RawMessage
	decodeBody(t, resp, &raw)

	// The secret appears exactly once, under its own key, plus inside the URI
	// the authenticator app scans. No third copy.
	if _, ok := raw["secret"]; !ok {
		t.Fatal("the response does not carry the secret")
	}
	for key := range raw {
		switch key {
		case "secret", "otpauth_uri", "enrollment_id", "algorithm", "digits", "period_seconds":
		default:
			t.Errorf("unexpected field %q in the enroll response", key)
		}
	}

	// The audit trail records the enrollment but never the secret.
	var leaked int
	if err := h.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE action LIKE 'mfa.%' AND (context::text LIKE '%secret%' OR reason LIKE '%secret%')`,
	).Scan(&leaked); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if leaked != 0 {
		t.Errorf("the audit trail mentions a secret in %d rows", leaked)
	}
}
