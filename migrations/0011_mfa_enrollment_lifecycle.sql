-- 0011_mfa_enrollment_lifecycle.sql — MFA enrollment lifecycle.
--
-- Why this migration exists:
--
-- 0002 declared `totp_credentials_active_idx` as UNIQUE (user_id) WHERE
-- disabled_at IS NULL. That permits at most ONE non-disabled enrollment per
-- user, which in turn forced CreateTOTPEnrollment to disable the existing
-- enrollment BEFORE inserting the replacement. The consequence was a second
-- factor DOWNGRADE: between the enroll and the confirm, the account had no
-- confirmed enrollment, so login stopped asking for a second factor. An
-- attacker holding a hijacked session could therefore call enroll and then
-- simply not confirm — no code needed — and the account's MFA was gone.
--
-- Splitting the constraint by lifecycle state makes the window impossible:
--
--   * at most one ACTIVE (confirmed, enabled) enrollment — the factor in force;
--   * at most one PENDING (unconfirmed, enabled) enrollment — a candidate.
--
-- A pending enrollment may now coexist with the active one, so enrolling an
-- authenticator cannot disarm the factor already protecting the account. The
-- old row is demoted to disabled only when the candidate is CONFIRMED, which is
-- the first moment the replacement is provably usable.

DROP INDEX totp_credentials_active_idx;

-- The enrollment in force. This is what GetActiveTOTP reads and what login
-- requires a code for.
CREATE UNIQUE INDEX totp_credentials_confirmed_active_idx
    ON totp_credentials (user_id)
    WHERE confirmed_at IS NOT NULL AND disabled_at IS NULL;

-- A candidate awaiting proof of possession. Never usable for login: no read
-- path returns it, and ConsumeTOTPStep requires confirmed_at IS NOT NULL.
CREATE UNIQUE INDEX totp_credentials_pending_idx
    ON totp_credentials (user_id)
    WHERE confirmed_at IS NULL AND disabled_at IS NULL;

-- Recovery-code lookup by digest is a read on the login path, so it needs an
-- index on the digest itself; the user-scoped index below only helps the count.
-- The hash is UNIQUE because two rows holding the same digest would make
-- single-use ambiguous: consuming one would leave an identical usable code.
CREATE UNIQUE INDEX recovery_codes_hash_idx ON recovery_codes (code_hash);
