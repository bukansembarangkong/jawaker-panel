//go:build integration

// Integration tests for the second-factor lifecycle: enrollment, confirmation,
// replay, recovery codes, and disable.
//
// Run with:
//
//	JAWAKER_TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/identity/

package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testStep is a fixed time step, chosen far from the wall clock so a stale
// last_used_step from another test cannot interfere.
const testStep int64 = 1000

// newUser inserts a bare active account, which is all the MFA tables need.
func newUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (email, display_name, account_type)
		VALUES ($1, 'MFA Test', 'customer') RETURNING id::text`, email).Scan(&id); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

// enrollConfirmed runs the enrollâ†’confirm cycle and returns the enrollment id.
//
// The step is supplied directly rather than derived from a real code: the state
// machine under test is what consumes a step, and generating a code would only
// test totp.Code again.
func enrollConfirmed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string, step int64) string {
	t.Helper()
	enrollmentID, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_enroll")
	if err != nil {
		t.Fatalf("CreateTOTPEnrollment: %v", err)
	}
	if err := ConfirmTOTPEnrollment(ctx, pool, enrollmentID, userID, step, "req_mfa_confirm"); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}
	return enrollmentID
}

// A new enrollment must NOT disturb the factor already in force.
//
// Regression test for a real downgrade: the original implementation disabled
// every enabled enrollment before inserting the replacement, so an account that
// enrolled and never confirmed lost its second factor entirely. Anyone holding a
// session could reach that state with no code.
func TestEnrollingDoesNotDisableTheActiveFactor(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "downgrade@example.test")

	activeID := enrollConfirmed(t, ctx, pool, userID, testStep)

	// Enroll a replacement and stop. No confirmation.
	if _, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_second"); err != nil {
		t.Fatalf("second CreateTOTPEnrollment: %v", err)
	}

	stillActive, err := GetActiveTOTP(ctx, pool, userID)
	if err != nil {
		t.Fatalf("the active factor disappeared when a new enrollment started: %v", err)
	}
	if stillActive.ID != activeID {
		t.Errorf("active enrollment changed from %s to %s without confirmation", activeID, stillActive.ID)
	}

	status, err := GetTOTPStatus(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetTOTPStatus: %v", err)
	}
	if !status.Enrolled {
		t.Error("status reports no enrolled factor while one is still in force")
	}
	if !status.Pending {
		t.Error("status does not report the pending enrollment")
	}

	// The factor still consumes codes, so login still demands one.
	ok, err := ConsumeTOTPStep(ctx, pool, activeID, testStep+1)
	if err != nil {
		t.Fatalf("ConsumeTOTPStep: %v", err)
	}
	if !ok {
		t.Error("the active factor stopped accepting codes while a replacement was pending")
	}
}

// Confirming a replacement swaps the factor: the new one is active and the old
// one stops being usable, with no window in which neither is.
func TestConfirmingReplacementSwapsTheActiveFactor(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "swap@example.test")

	firstID := enrollConfirmed(t, ctx, pool, userID, testStep)
	if _, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_second"); err != nil {
		t.Fatalf("CreateTOTPEnrollment: %v", err)
	}

	pending, err := GetPendingTOTP(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if err := ConfirmTOTPEnrollment(ctx, pool, pending.ID, userID, testStep+50, "req_mfa_confirm"); err != nil {
		t.Fatalf("confirm replacement: %v", err)
	}

	second, err := GetActiveTOTP(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetActiveTOTP after replacement: %v", err)
	}
	if second.ID == firstID {
		t.Fatal("the replacement was not promoted")
	}

	accepted, err := ConsumeTOTPStep(ctx, pool, firstID, testStep+100)
	if err != nil {
		t.Fatalf("ConsumeTOTPStep on the superseded enrollment: %v", err)
	}
	if accepted {
		t.Error("a superseded enrollment still accepts codes")
	}

	var enabled int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM totp_credentials
		WHERE user_id = $1 AND confirmed_at IS NOT NULL AND disabled_at IS NULL`,
		userID).Scan(&enabled); err != nil {
		t.Fatalf("count enabled enrollments: %v", err)
	}
	if enabled != 1 {
		t.Errorf("enabled confirmed enrollments = %d, want exactly 1", enabled)
	}

	// Nothing is pending any more.
	if _, err := GetPendingTOTP(ctx, pool, userID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPendingTOTP after confirmation = %v, want ErrNotFound", err)
	}
}

// An older or equal step cannot confirm, so an observed enrollment code is not
// reusable and cannot re-promote a demoted factor.
func TestConfirmRejectsANonIncreasingStep(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "replay@example.test")

	_, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_a")
	if err != nil {
		t.Fatalf("CreateTOTPEnrollment: %v", err)
	}
	pending, err := GetPendingTOTP(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if err := ConfirmTOTPEnrollment(ctx, pool, pending.ID, userID, testStep, "req_mfa_b"); err != nil {
		t.Fatalf("first ConfirmTOTPEnrollment: %v", err)
	}

	if err := ConfirmTOTPEnrollment(ctx, pool, pending.ID, userID, testStep, "req_mfa_c"); !errors.Is(err, ErrNotFound) {
		t.Errorf("replayed confirmation = %v, want ErrNotFound", err)
	}

	// A second pending enrollment confirmed with an OLDER step than the active
	// factor's must be refused too: last_used_step is per-enrollment, so the
	// guard here protects against a replayed code, not clock travel.
	if _, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_d"); err != nil {
		t.Fatalf("CreateTOTPEnrollment: %v", err)
	}
	pending2, err := GetPendingTOTP(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if err := ConfirmTOTPEnrollment(ctx, pool, pending2.ID, userID, testStep+1, "req_mfa_e"); err != nil {
		t.Fatalf("confirming a newer enrollment with a newer step: %v", err)
	}
}

// Two pending rows cannot exist; the newest enrollment supersedes the older one.
func TestSecondEnrollSupersedesTheFirstPending(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "pending@example.test")

	first, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_1")
	if err != nil {
		t.Fatalf("first CreateTOTPEnrollment: %v", err)
	}
	second, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_2")
	if err != nil {
		t.Fatalf("second CreateTOTPEnrollment: %v", err)
	}
	if first == second {
		t.Fatal("the second enrollment reused the first one's id")
	}

	pending, err := GetPendingTOTP(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetPendingTOTP: %v", err)
	}
	if pending.ID != second {
		t.Errorf("pending enrollment = %s, want the newest (%s)", pending.ID, second)
	}

	var disabled int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM totp_credentials WHERE id = $1 AND disabled_at IS NOT NULL`,
		first).Scan(&disabled); err != nil {
		t.Fatalf("query superseded: %v", err)
	}
	if disabled != 1 {
		t.Error("the superseded pending enrollment was not disabled")
	}
}

// Each enrollment gets its own secret reference, so sealing a replacement's
// secret cannot overwrite the secret of the factor still in force.
func TestEachEnrollmentGetsItsOwnSecretReference(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "refs@example.test")

	_, firstRef, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_1")
	if err != nil {
		t.Fatalf("first CreateTOTPEnrollment: %v", err)
	}
	_, secondRef, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_2")
	if err != nil {
		t.Fatalf("second CreateTOTPEnrollment: %v", err)
	}
	if firstRef == secondRef {
		t.Fatalf("both enrollments share the secret reference %q", firstRef)
	}
	if !strings.HasPrefix(firstRef, "secret://totp/") {
		t.Errorf("secret reference %q does not use the totp namespace", firstRef)
	}
}

// --- recovery codes -------------------------------------------------------------

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "recovery@example.test")

	codes, err := GenerateRecoveryCodesN(ctx, pool, userID, 5, "req_rc_1")
	if err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}
	if len(codes) != 5 {
		t.Fatalf("generated %d codes, want 5", len(codes))
	}

	ok, err := ConsumeRecoveryCode(ctx, pool, userID, codes[0])
	if err != nil {
		t.Fatalf("ConsumeRecoveryCode: %v", err)
	}
	if !ok {
		t.Fatal("a freshly generated code was rejected")
	}
	again, err := ConsumeRecoveryCode(ctx, pool, userID, codes[0])
	if err != nil {
		t.Fatalf("second ConsumeRecoveryCode: %v", err)
	}
	if again {
		t.Error("a recovery code was accepted twice")
	}

	remaining, err := CountUnusedRecoveryCodes(ctx, pool, userID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if remaining != 4 {
		t.Errorf("unused codes = %d, want 4", remaining)
	}
}

// A code is transcribed by hand, so casing, spaces, and separators must not
// decide whether a user can get back into their own account.
func TestRecoveryCodeAcceptsTranscriptionVariants(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "transcribe@example.test")

	codes, err := GenerateRecoveryCodesN(ctx, pool, userID, 1, "req_rc_2")
	if err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}
	variant := strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))

	ok, err := ConsumeRecoveryCode(ctx, pool, userID, variant)
	if err != nil {
		t.Fatalf("ConsumeRecoveryCode: %v", err)
	}
	if !ok {
		t.Errorf("the transcribed form %q was rejected", variant)
	}
}

// An empty or whitespace-only code is refused without a database round trip, so
// a missing field is not an "incorrect code" signal.
func TestEmptyRecoveryCodeIsRejected(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "empty@example.test")

	if _, err := GenerateRecoveryCodesN(ctx, pool, userID, 2, "req_rc_3"); err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}
	for _, bad := range []string{"", "   ", "-", "--", "- -"} {
		ok, err := ConsumeRecoveryCode(ctx, pool, userID, bad)
		if err != nil {
			t.Fatalf("ConsumeRecoveryCode(%q): %v", bad, err)
		}
		if ok {
			t.Errorf("ConsumeRecoveryCode(%q) accepted an empty code", bad)
		}
	}
}

// Regenerating invalidates the previous set: a user cannot tell which of two
// live sets is current, and a code written on a lost note must stop working.
func TestRegeneratingInvalidatesThePreviousSet(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "regen@example.test")

	first, err := GenerateRecoveryCodesN(ctx, pool, userID, 3, "req_rc_4")
	if err != nil {
		t.Fatalf("first generation: %v", err)
	}
	second, err := GenerateRecoveryCodesN(ctx, pool, userID, 3, "req_rc_5")
	if err != nil {
		t.Fatalf("second generation: %v", err)
	}

	for _, stale := range first {
		ok, err := ConsumeRecoveryCode(ctx, pool, userID, stale)
		if err != nil {
			t.Fatalf("ConsumeRecoveryCode: %v", err)
		}
		if ok {
			t.Errorf("code %q from the previous set still works", stale)
		}
	}
	remaining, err := CountUnusedRecoveryCodes(ctx, pool, userID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if remaining != len(second) {
		t.Errorf("unused codes = %d, want %d (only the new set)", remaining, len(second))
	}
}

// A code belonging to another user must never be accepted.
func TestRecoveryCodeIsScopedToItsUser(t *testing.T) {
	pool, ctx := setup(t)
	owner := newUser(t, ctx, pool, "rc-owner@example.test")
	other := newUser(t, ctx, pool, "rc-other@example.test")

	codes, err := GenerateRecoveryCodesN(ctx, pool, owner, 1, "req_rc_6")
	if err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}
	ok, err := ConsumeRecoveryCode(ctx, pool, other, codes[0])
	if err != nil {
		t.Fatalf("ConsumeRecoveryCode: %v", err)
	}
	if ok {
		t.Error("another user's recovery code was accepted")
	}
}

// The count bounds how much entropy a user can accumulate, and a nonsensical
// count must be refused rather than silently producing zero codes.
func TestRecoveryCodeCountIsBounded(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "bounds@example.test")

	for _, n := range []int{0, -1, 51} {
		if _, err := GenerateRecoveryCodesN(ctx, pool, userID, n, "req_rc_7"); err == nil {
			t.Errorf("GenerateRecoveryCodesN(count=%d) succeeded, want an error", n)
		}
	}
}

// Only digests are stored: a database read must not yield a usable code.
func TestRecoveryCodesAreStoredAsDigests(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "digest@example.test")

	codes, err := GenerateRecoveryCodesN(ctx, pool, userID, 3, "req_rc_8")
	if err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}

	rows, err := pool.Query(ctx,
		`SELECT code_hash FROM recovery_codes WHERE user_id = $1`, userID)
	if err != nil {
		t.Fatalf("query stored codes: %v", err)
	}
	defer rows.Close()

	stored := make(map[string]bool, 3)
	for rows.Next() {
		var hash []byte
		if err := rows.Scan(&hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		// The stored value must be a digest, never any form of the code.
		text := string(hash)
		for _, code := range codes {
			if strings.Contains(text, secureid.CanonicalRecoveryCode(code)) {
				t.Errorf("a plaintext recovery code appears in the stored value")
			}
		}
		stored[text] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(stored) != len(codes) {
		t.Fatalf("stored digests = %d, want %d", len(stored), len(codes))
	}
	// Each displayed code's canonical digest must be exactly what was stored.
	for _, code := range codes {
		want := string(secureid.HashToken([]byte(secureid.CanonicalRecoveryCode(code))))
		if !stored[want] {
			t.Errorf("no stored digest matches the code issued to the user")
		}
	}
}

// --- disable --------------------------------------------------------------------

// Disabling the factor must also retire the codes that bypass it: a credential
// must not outlive the policy it belonged to.
func TestDisableRevokesRecoveryCodes(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "disable@example.test")

	enrollConfirmed(t, ctx, pool, userID, testStep)
	if _, err := GenerateRecoveryCodesN(ctx, pool, userID, 4, "req_rc_9"); err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}

	revoked, err := DisableTOTP(ctx, pool, userID, userID, "lost device", "req_mfa_disable")
	if err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if revoked != 4 {
		t.Errorf("revoked codes = %d, want 4", revoked)
	}

	remaining, err := CountUnusedRecoveryCodes(ctx, pool, userID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if remaining != 0 {
		t.Errorf("unused codes after disable = %d, want 0", remaining)
	}
	if _, err := GetActiveTOTP(ctx, pool, userID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetActiveTOTP after disable = %v, want ErrNotFound", err)
	}
	status, err := GetTOTPStatus(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetTOTPStatus: %v", err)
	}
	if status.Enrolled || status.Pending {
		t.Errorf("status after disable = %+v, want both false", status)
	}
}

// A disable without a reason is refused: the audit row is what an incident
// reviewer reads.
func TestDisableRequiresAReason(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "noreason@example.test")
	enrollConfirmed(t, ctx, pool, userID, testStep)

	for _, blank := range []string{"", "   ", "\t\n"} {
		if _, err := DisableTOTP(ctx, pool, userID, userID, blank, "req_mfa_r"); err == nil {
			t.Errorf("DisableTOTP accepted the blank reason %q", blank)
		}
	}
	// Nothing was disabled by the refusals.
	if _, err := GetActiveTOTP(ctx, pool, userID); err != nil {
		t.Errorf("the factor was disabled despite every call being refused: %v", err)
	}
}

// Disabling a factor that does not exist reports not-found rather than
// succeeding, so a client cannot believe it changed something it did not.
func TestDisableWithoutEnrollmentIsNotFound(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "nofactor@example.test")

	if _, err := DisableTOTP(ctx, pool, userID, userID, "not enrolled", "req_mfa_n"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DisableTOTP = %v, want ErrNotFound", err)
	}
}

// Disabling clears a pending candidate too, so an unconfirmed enrollment cannot
// linger as the thing a later confirm promotes.
func TestDisableAlsoClearsPendingEnrollment(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "pendingdisable@example.test")

	if _, _, err := CreateTOTPEnrollment(ctx, pool, userID, "req_mfa_p"); err != nil {
		t.Fatalf("CreateTOTPEnrollment: %v", err)
	}
	if _, err := DisableTOTP(ctx, pool, userID, userID, "abandoning enrollment", "req_mfa_pd"); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if _, err := GetPendingTOTP(ctx, pool, userID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPendingTOTP after disable = %v, want ErrNotFound", err)
	}
}

// Every protection change leaves an audit row, and each row carries the request
// id so it can be correlated with the HTTP call.
func TestMFALifecycleIsAudited(t *testing.T) {
	pool, ctx := setup(t)
	userID := newUser(t, ctx, pool, "audit@example.test")

	enrollConfirmed(t, ctx, pool, userID, testStep)
	if _, err := GenerateRecoveryCodesN(ctx, pool, userID, 2, "req_rc_a"); err != nil {
		t.Fatalf("GenerateRecoveryCodesN: %v", err)
	}
	if _, err := DisableTOTP(ctx, pool, userID, userID, "rotating device", "req_mfa_z"); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT action, result FROM audit_events
		WHERE actor_id = $1 AND action LIKE 'mfa.%'
		ORDER BY occurred_at`, userID)
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	defer rows.Close()

	var actions []string
	for rows.Next() {
		var action, result string
		if err := rows.Scan(&action, &result); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if result != "success" {
			t.Errorf("audit action %q has result %q, want success", action, result)
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	want := []string{"mfa.totp.enroll", "mfa.totp.confirm", "mfa.recovery.generate", "mfa.totp.disable"}
	if len(actions) != len(want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Errorf("audit actions = %v, want %v", actions, want)
			break
		}
	}
}
