-- 0002_identity.sql — identity domain.
--
-- Scope: users, credential material, browser sessions, and MFA enrollment.
-- Design notes:
--   * Opaque UUID primary keys (DATABASE.md s4: never expose sequential IDs).
--   * Timestamps are timestamptz; the application always writes UTC.
--   * Soft deletion via `state` (DATABASE.md s7) so audit references to a
--     user remain resolvable after deactivation.
--   * Password/TOTP secret VALUES never live here; only hashes and envelope
--     references. Secret material stays in the secret subsystem (SECURITY.md s8).
--
-- 0001_init is released and immutable, so the extension is enabled here at
-- first use. IF NOT EXISTS keeps re-application across environments safe.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Unique, case-insensitive login identifier. Display name is separate.
    email           citext NOT NULL UNIQUE,
    display_name    text NOT NULL,
    -- active | suspended | pending_delete | deleted
    state           text NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'suspended', 'pending_delete', 'deleted')),
    -- Platform Owner / Server Admin / Reseller / Customer; role bindings carry
    -- the granular permissions, this is the coarse account class.
    account_type    text NOT NULL DEFAULT 'customer'
                    CHECK (account_type IN ('platform_owner', 'server_admin', 'reseller', 'customer')),
    is_owner        boolean NOT NULL DEFAULT false,
    -- Brute-force state (SECURITY.md s3). Reset on successful authentication.
    failed_login_count integer NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE INDEX users_state_idx ON users (state) WHERE deleted_at IS NULL;

-- Exactly one platform owner may exist. Enforced in the database rather than
-- in application logic so a race between two bootstrap attempts cannot create
-- two owners (DATABASE.md s16: do not rely on in-process mutexes).
CREATE UNIQUE INDEX users_single_owner_idx ON users (is_owner) WHERE is_owner;

-- Password credentials, versioned to support rotation without losing history.
CREATE TABLE password_credentials (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- argon2id encoded string (algorithm, params, salt, hash). Never a raw hash.
    password_hash     text NOT NULL,
    algorithm         text NOT NULL DEFAULT 'argon2id',
    -- Superseded rows are retained (not deleted) so credential rotation is
    -- auditable and an interrupted rotation can be reasoned about.
    superseded_at     timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- At most one active password per user.
CREATE UNIQUE INDEX password_credentials_active_idx
    ON password_credentials (user_id) WHERE superseded_at IS NULL;

CREATE TABLE sessions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the opaque session token. The token itself is never stored,
    -- so a database read cannot be replayed as a live session (SECURITY.md s4).
    token_hash        bytea NOT NULL UNIQUE,
    -- Rotated on privilege change / re-authentication; old id links the chain.
    previous_session_id uuid REFERENCES sessions (id) ON DELETE SET NULL,
    -- Device/session inventory metadata (SECURITY.md s4).
    user_agent        text,
    client_ip         inet,
    -- Short-lived elevation for sensitive operations (step-up auth).
    elevated_until    timestamptz,
    -- Trusted-network restriction for privileged roles.
    absolute_expires_at timestamptz NOT NULL,
    idle_expires_at   timestamptz NOT NULL,
    revoked_at        timestamptz,
    revoke_reason     text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx ON sessions (idle_expires_at) WHERE revoked_at IS NULL;

-- TOTP enrollment. Passkey/WebAuthn rows join this table family in a later
-- migration; the interface is designed to accept them without schema churn.
CREATE TABLE totp_credentials (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Secret is sealed by the secret subsystem; only the reference is stored.
    secret_ref        text NOT NULL,
    -- Confirmed enrollments only become usable.
    confirmed_at      timestamptz,
    -- Anti-replay: the last accepted time step must never be reused.
    last_used_step    bigint,
    created_at        timestamptz NOT NULL DEFAULT now(),
    disabled_at       timestamptz
);

CREATE UNIQUE INDEX totp_credentials_active_idx
    ON totp_credentials (user_id) WHERE disabled_at IS NULL;

-- Single-use recovery codes, stored only as hashes.
CREATE TABLE recovery_codes (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash         bytea NOT NULL,
    used_at           timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE used_at IS NULL;
