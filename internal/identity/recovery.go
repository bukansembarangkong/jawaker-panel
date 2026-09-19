package identity

import (
	"context"
	"fmt"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
)

// Single-use recovery codes (SECURITY.md §3: recovery codes with secure
// handling). Only the SHA-256 digest is stored, so a database read yields no
// usable code. Codes are shown to the user exactly once, at generation.

// DefaultRecoveryCodeCount is the number of codes issued per generation. It
// matches the common authenticator-app convention; fewer is not enough to
// survive a lost device plus a few typos, and many more is inventory the user
// will never transcribe.
const DefaultRecoveryCodeCount = 10

// GenerateRecoveryCodes replaces a user's recovery codes with a fresh set and
// returns the plaintext codes.
//
// Replacement rather than accumulation is the safe default: codes from an
// earlier generation may have been transcribed onto a lost note, and the user
// cannot tell which set is current if both remain valid. Invalidating the old
// set makes "the codes I have are the codes that work" true.
//
// The returned plaintext is the ONLY time the codes exist outside the user's
// hands; nothing is logged and no caller may persist them.
func GenerateRecoveryCodes(ctx context.Context, db Querier, userID, requestID string) ([]string, error) {
	return GenerateRecoveryCodesN(ctx, db, userID, DefaultRecoveryCodeCount, requestID)
}

// GenerateRecoveryCodesN is GenerateRecoveryCodes with an explicit count.
func GenerateRecoveryCodesN(ctx context.Context, db Querier, userID string, count int, requestID string) ([]string, error) {
	if count <= 0 || count > 50 {
		return nil, fmt.Errorf("identity: recovery code count %d is out of range (1..50)", count)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: begin recovery code generation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Retire the previous set. Rows are DELETED rather than marked used: a used
	// flag on a retired code would imply it was consumed by someone, which is a
	// different (and alarming) fact than "superseded by a rotation". The audit
	// row records the rotation.
	if _, err := tx.Exec(ctx,
		`DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return nil, fmt.Errorf("identity: retire previous recovery codes: %w", err)
	}

	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code, hash, genErr := secureid.RecoveryCode()
		if genErr != nil {
			return nil, fmt.Errorf("identity: generate recovery code: %w", genErr)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, hash); err != nil {
			return nil, fmt.Errorf("identity: store recovery code: %w", err)
		}
		codes = append(codes, code)
	}

	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      userID,
		Action:       "mfa.recovery.generate",
		ResourceType: "user",
		ResourceID:   userID,
		RequestID:    requestID,
		Result:       audit.ResultSuccess,
		Context:      map[string]any{"count": count},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("identity: commit recovery code generation: %w", err)
	}
	return codes, nil
}

// ConsumeRecoveryCode redeems one code, returning false when no unused code
// matches.
//
// Single-use is enforced by a conditional UPDATE in the DATABASE, not by a read
// followed by a write: two requests presenting the same code race there, and
// exactly one sees rowsAffected == 1. An application-side check-then-act would
// let both through, which is exactly what a replayed code depends on.
//
// The digest is compared by lookup rather than by iterating stored codes, so a
// wrong code costs one indexed probe instead of a full user scan.
func ConsumeRecoveryCode(ctx context.Context, db Execer, userID, code string) (bool, error) {
	normalized := secureid.CanonicalRecoveryCode(code)
	if normalized == "" {
		return false, nil
	}
	tag, err := db.Exec(ctx, `
		UPDATE recovery_codes SET used_at = now()
		WHERE id = (
			SELECT id FROM recovery_codes
			WHERE user_id = $1 AND used_at IS NULL
			  AND code_hash = $2
			LIMIT 1
		)`, userID, secureid.HashToken([]byte(normalized)))
	if err != nil {
		return false, fmt.Errorf("identity: consume recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountUnusedRecoveryCodes reports how many codes remain, so the UI can warn a
// user who has spent most of them without exposing the codes themselves.
func CountUnusedRecoveryCodes(ctx context.Context, db Queryer, userID string) (int, error) {
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("identity: count recovery codes: %w", err)
	}
	return n, nil
}

// RevokeRecoveryCodes deletes a user's codes. Called when the second factor is
// disabled: codes are a bypass for a factor that no longer exists, and leaving
// them valid would let an attacker who has none of the account's factors still
// satisfy the "second factor" step.
func RevokeRecoveryCodes(ctx context.Context, db Execer, userID string) (int64, error) {
	tag, err := db.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("identity: revoke recovery codes: %w", err)
	}
	return tag.RowsAffected(), nil
}
