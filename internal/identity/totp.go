package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/jackc/pgx/v5"
)

// TOTP enrollment lifecycle (SECURITY.md §3: TOTP 2FA).
//
// The shared secret itself never lives in this table: totp_credentials stores
// only a `secret://` reference into the secret subsystem, so a database dump
// does not yield working second factors.

// TOTPCredential is one enrollment row.
type TOTPCredential struct {
	ID string
	// SecretRef points into the secret subsystem.
	SecretRef string
	// ConfirmedAt is nil until the user proves possession of the secret by
	// submitting a valid code. An unconfirmed enrollment is never usable.
	ConfirmedAt *time.Time
	// LastUsedStep is the most recently consumed time step (anti-replay).
	LastUsedStep *int64
	CreatedAt    time.Time
	DisabledAt   *time.Time
}

// CreateTOTPEnrollment creates an UNCONFIRMED enrollment with its secret
// reference.
//
// Confirmation is a separate step on purpose: an enrollment that is usable
// immediately would lock a user out of their own account the moment the
// provisioning step fails, e.g. a mistyped scan.
func CreateTOTPEnrollment(ctx context.Context, db Querier, userID, secretRef string, requestID string) (string, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("identity: begin TOTP enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Disable any previous enrollment so the partial unique index admits this
	// one. The old row is retained because a disabled enrollment is part of the
	// account's security history.
	if _, err := tx.Exec(ctx, `
		UPDATE totp_credentials SET disabled_at = now()
		WHERE user_id = $1 AND disabled_at IS NULL`, userID); err != nil {
		return "", fmt.Errorf("identity: disable previous enrollment: %w", err)
	}

	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO totp_credentials (user_id, secret_ref)
		VALUES ($1, $2) RETURNING id`, userID, secretRef).Scan(&id); err != nil {
		return "", fmt.Errorf("identity: create TOTP enrollment: %w", err)
	}

	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      userID,
		Action:       "mfa.totp.enroll",
		ResourceType: "totp_credential",
		ResourceID:   id,
		RequestID:    requestID,
		Result:       audit.ResultSuccess,
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("identity: commit TOTP enrollment: %w", err)
	}
	return id, nil
}

// GetTOTPEnrollment loads one enrollment by id.
func GetTOTPEnrollment(ctx context.Context, db Queryer, id string) (TOTPCredential, error) {
	return scanTOTP(db.QueryRow(ctx, `
		SELECT id, secret_ref, confirmed_at, last_used_step, created_at, disabled_at
		FROM totp_credentials WHERE id = $1`, id))
}

// GetActiveTOTP loads the confirmed, enabled enrollment for a user.
//
// A user with an UNCONFIRMED enrollment has ErrNotFound here, which is what
// keeps a half-finished enrollment from requiring a second factor nobody can
// produce.
func GetActiveTOTP(ctx context.Context, db Queryer, userID string) (TOTPCredential, error) {
	return scanTOTP(db.QueryRow(ctx, `
		SELECT id, secret_ref, confirmed_at, last_used_step, created_at, disabled_at
		FROM totp_credentials
		WHERE user_id = $1 AND confirmed_at IS NOT NULL AND disabled_at IS NULL
		ORDER BY confirmed_at DESC LIMIT 1`, userID))
}

func scanTOTP(row pgx.Row) (TOTPCredential, error) {
	var c TOTPCredential
	err := row.Scan(&c.ID, &c.SecretRef, &c.ConfirmedAt, &c.LastUsedStep,
		&c.CreatedAt, &c.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TOTPCredential{}, ErrNotFound
	}
	if err != nil {
		return TOTPCredential{}, fmt.Errorf("identity: load TOTP enrollment: %w", err)
	}
	return c, nil
}

// ConfirmTOTPEnrollment marks an enrollment usable after the user has proven
// possession of the secret, and audits the change.
//
// Confirming MFA is a security-relevant state change: an account whose second
// factor appeared without a trail is indistinguishable from one whose factor
// was added by an attacker, so the write and its audit row commit together.
func ConfirmTOTPEnrollment(ctx context.Context, db Querier, enrollmentID, actorID, requestID string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin TOTP confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE totp_credentials SET confirmed_at = now()
		WHERE id = $1 AND confirmed_at IS NULL AND disabled_at IS NULL`, enrollmentID)
	if err != nil {
		return fmt.Errorf("identity: confirm TOTP enrollment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Already confirmed, disabled, or unknown. Reported as not-found rather
		// than silently succeeding, so a double confirmation is visible.
		return ErrNotFound
	}
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      actorID,
		Action:       "mfa.totp.confirm",
		ResourceType: "totp_credential",
		ResourceID:   enrollmentID,
		RequestID:    requestID,
		Result:       audit.ResultSuccess,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("identity: commit TOTP confirmation: %w", err)
	}
	return nil
}

// ConsumeTOTPStep records a time step as used, returning false when it was
// already consumed.
//
// This is the anti-replay guarantee. It runs as a single conditional UPDATE, so
// two requests presenting the same code race in the DATABASE: exactly one gets
// rowsAffected == 1. A read-then-write in application code would let both in,
// because both reads would complete before either write — the classic
// check-then-act race, and precisely the case an attacker replaying an observed
// code would exploit.
//
// The step must be monotonic: an older step is refused even if unused, so a code
// captured earlier cannot be replayed later in the window.
func ConsumeTOTPStep(ctx context.Context, db Execer, enrollmentID string, step int64) (bool, error) {
	tag, err := db.Exec(ctx, `
		UPDATE totp_credentials
		SET last_used_step = $2
		WHERE id = $1
		  AND confirmed_at IS NOT NULL
		  AND disabled_at IS NULL
		  AND (last_used_step IS NULL OR last_used_step < $2)`, enrollmentID, step)
	if err != nil {
		return false, fmt.Errorf("identity: consume TOTP step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DisableTOTP disables the active enrollment and audits it. Used when a user
// loses their authenticator: the row is retained with disabled_at so the history
// of enrollments stays visible.
//
// Disabling a second factor is the single highest-impact identity change an
// account owner can make, so it is audited transactionally with the reason
// recorded: an account whose MFA vanished without explanation is exactly the
// signal an incident reviewer needs.
func DisableTOTP(ctx context.Context, db Querier, userID, actorID, reason, requestID string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("identity: a reason is required to disable a second factor")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin TOTP disable: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE totp_credentials SET disabled_at = now()
		WHERE user_id = $1 AND disabled_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("identity: disable TOTP: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      actorID,
		Action:       "mfa.totp.disable",
		ResourceType: "user",
		ResourceID:   userID,
		RequestID:    requestID,
		Result:       audit.ResultSuccess,
		Reason:       reason,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("identity: commit TOTP disable: %w", err)
	}
	return nil
}

// TOTPStatus summarizes a user's second-factor state for the UI.
type TOTPStatus struct {
	// Enrolled reports a confirmed, enabled enrollment.
	Enrolled bool
	// Pending reports an unconfirmed enrollment awaiting confirmation.
	Pending bool
}

// GetTOTPStatus reports the second-factor state without exposing the secret.
func GetTOTPStatus(ctx context.Context, db Queryer, userID string) (TOTPStatus, error) {
	var status TOTPStatus
	err := db.QueryRow(ctx, `
		SELECT
		  EXISTS (SELECT 1 FROM totp_credentials
		           WHERE user_id = $1 AND confirmed_at IS NOT NULL AND disabled_at IS NULL),
		  EXISTS (SELECT 1 FROM totp_credentials
		           WHERE user_id = $1 AND confirmed_at IS NULL AND disabled_at IS NULL)`,
		userID).Scan(&status.Enrolled, &status.Pending)
	if err != nil {
		return TOTPStatus{}, fmt.Errorf("identity: TOTP status: %w", err)
	}
	return status, nil
}
