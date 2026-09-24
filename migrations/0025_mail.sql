-- 0025_mail.sql: Mail platform — domains, mailboxes, aliases, forwarders,
-- DKIM keys, queue/log tracing, rate/abuse limits.
-- Phase 13. Mail modules remain optional/removable.

-- Mail domains: one row per hosted domain per project.
CREATE TABLE mail_domains (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    server_id  UUID NOT NULL REFERENCES servers(id)  ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'pending'
                   CHECK (state IN ('pending', 'active', 'error', 'disabled')),
    spf_ok     BOOLEAN,
    dkim_ok    BOOLEAN,
    dmarc_ok   BOOLEAN,
    last_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, domain)
);

-- Mailboxes: one per email address.
CREATE TABLE mailboxes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    local_part  TEXT NOT NULL CHECK (local_part ~ '^[a-zA-Z0-9._%+\-]+$'),
    state       TEXT NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'disabled', 'deleted')),
    quota_mb    INT  NOT NULL DEFAULT 1024 CHECK (quota_mb > 0),
    -- password_ref is a secret URI (sealed, never plaintext in DB)
    password_ref TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE (domain_id, local_part)
);

-- Aliases: redirect one address to another.
CREATE TABLE mail_aliases (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    local_part  TEXT NOT NULL CHECK (local_part ~ '^[a-zA-Z0-9._%+\-]+$'),
    destination TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, local_part)
);

-- Forwarders: forward all mail for a domain to an external address.
CREATE TABLE mail_forwarders (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    keep_local  BOOLEAN NOT NULL DEFAULT false,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- DKIM keys: per-domain signing keys.
CREATE TABLE dkim_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    selector    TEXT NOT NULL,
    -- key_ref is a secret URI; private key never stored plaintext
    key_ref     TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    algorithm   TEXT NOT NULL DEFAULT 'rsa-sha256' CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at  TIMESTAMPTZ,
    UNIQUE (domain_id, selector)
);

-- Rate/abuse limits per domain.
CREATE TABLE mail_rate_limits (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id      UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE UNIQUE,
    max_per_hour   INT NOT NULL DEFAULT 500  CHECK (max_per_hour > 0),
    max_per_day    INT NOT NULL DEFAULT 5000 CHECK (max_per_day > 0),
    max_rcpt       INT NOT NULL DEFAULT 50   CHECK (max_rcpt > 0),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Queue/log tracing: sampled outbound message records.
CREATE TABLE mail_queue_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    queue_id    TEXT NOT NULL,
    from_addr   TEXT NOT NULL,
    to_addr     TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('queued', 'sent', 'deferred', 'bounced', 'rejected')),
    message     TEXT,
    logged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX mail_domains_project_idx   ON mail_domains  (project_id, state);
CREATE INDEX mailboxes_domain_idx       ON mailboxes      (domain_id, state);
CREATE INDEX mail_aliases_domain_idx    ON mail_aliases   (domain_id, enabled);
CREATE INDEX mail_queue_log_domain_idx  ON mail_queue_log (domain_id, logged_at DESC);
