-- 0030_api_tokens.sql — API tokens for programmatic access (PRD §26.2).
--
-- Tokens are stored as SHA-256 hashes. The plaintext token is returned exactly
-- once at creation and never persisted. Usage is logged for audit and rate
-- limiting. Revocation is immediate and irreversible.

CREATE TABLE api_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Human label, unique per user so operators can tell tokens apart.
    name            text NOT NULL,
    -- personal | service
    kind            text NOT NULL DEFAULT 'personal'
                    CHECK (kind IN ('personal', 'service')),
    -- SHA-256 of the raw token. Lookup key. Never the token itself.
    token_hash      bytea NOT NULL UNIQUE,
    -- Prefix shown in UI so a leaked token can be identified without the secret.
    token_prefix    text NOT NULL,
    -- Permission scopes granted to this token. Empty means inherit user grants.
    scopes          text[] NOT NULL DEFAULT '{}',
    -- Optional CIDR allow-list. Empty means any address.
    allowed_cidrs   text[] NOT NULL DEFAULT '{}',
    expires_at      timestamptz,
    revoked_at      timestamptz,
    last_used_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX api_tokens_user_idx ON api_tokens (user_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX api_tokens_name_user_idx ON api_tokens (user_id, name) WHERE revoked_at IS NULL;

-- Usage log: one row per authenticated request that used the token.
-- Retention is the operator's job; the table itself is append-only.
CREATE TABLE api_token_usage (
    id          bigserial PRIMARY KEY,
    token_id    uuid NOT NULL REFERENCES api_tokens (id) ON DELETE CASCADE,
    used_at     timestamptz NOT NULL DEFAULT now(),
    client_addr text,
    method      text,
    path        text,
    status      integer
);

CREATE INDEX api_token_usage_token_idx ON api_token_usage (token_id, used_at DESC);
