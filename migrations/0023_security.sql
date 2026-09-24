-- Phase 11: Security Center
-- Tables: hardening_checks, ssh_posture_log, security_events, ban_entries, waf_rules

-- Hardening check results per server
CREATE TABLE hardening_checks (
    id              UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    server_id       TEXT        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    check_name      TEXT        NOT NULL,
    category        TEXT        NOT NULL DEFAULT 'os',
    severity        TEXT        NOT NULL DEFAULT 'info',
    status          TEXT        NOT NULL DEFAULT 'pass',
    title           TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    remediation     TEXT        NOT NULL DEFAULT '',
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT hardening_checks_category_ok CHECK (
        category IN ('os', 'ssh', 'firewall', 'packages', 'services', 'network')
    ),
    CONSTRAINT hardening_checks_severity_ok CHECK (
        severity IN ('critical', 'high', 'medium', 'low', 'info')
    ),
    CONSTRAINT hardening_checks_status_ok CHECK (
        status IN ('pass', 'fail', 'warn', 'skip')
    )
);

CREATE INDEX hardening_checks_server_idx ON hardening_checks (server_id, observed_at DESC);

-- SSH posture snapshots
CREATE TABLE ssh_posture_log (
    id                  UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    server_id           TEXT        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    permit_root_login   TEXT        NOT NULL DEFAULT 'unknown',
    password_auth       TEXT        NOT NULL DEFAULT 'unknown',
    pubkey_auth         TEXT        NOT NULL DEFAULT 'unknown',
    port                INTEGER     NOT NULL DEFAULT 22,
    protocol_versions   TEXT        NOT NULL DEFAULT '',
    active_sessions     INTEGER     NOT NULL DEFAULT 0,
    auth_failures_1h    INTEGER     NOT NULL DEFAULT 0,
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ssh_posture_server_idx ON ssh_posture_log (server_id, observed_at DESC);

-- Security events (auth failures, intrusion attempts, ban events)
CREATE TABLE security_events (
    id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    server_id   TEXT        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    source      TEXT        NOT NULL DEFAULT 'system',
    kind        TEXT        NOT NULL DEFAULT 'auth_fail',
    remote_ip   TEXT        NOT NULL DEFAULT '',
    country     TEXT        NOT NULL DEFAULT '',
    service     TEXT        NOT NULL DEFAULT '',
    raw_line    TEXT        NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT security_events_kind_ok CHECK (
        kind IN ('auth_fail', 'ban', 'unban', 'intrusion', 'anomaly', 'scan')
    )
);

CREATE INDEX security_events_server_time_idx ON security_events (server_id, observed_at DESC);
CREATE INDEX security_events_ip_idx         ON security_events (server_id, remote_ip);

-- Active ban entries (fail2ban / crowdsec / manual)
CREATE TABLE ban_entries (
    id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    server_id   TEXT        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip          TEXT        NOT NULL,
    source      TEXT        NOT NULL DEFAULT 'manual',
    reason      TEXT        NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ,
    banned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unbanned_at TIMESTAMPTZ,
    state       TEXT        NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ban_entries_state_ok CHECK (
        state IN ('active', 'expired', 'removed')
    )
);

CREATE UNIQUE INDEX ban_entries_active_ip_idx ON ban_entries (server_id, ip) WHERE state = 'active';
CREATE INDEX ban_entries_server_idx ON ban_entries (server_id, banned_at DESC);

-- WAF / rate-limit rules
CREATE TABLE waf_rules (
    id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    server_id   TEXT        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kind        TEXT        NOT NULL DEFAULT 'rate_limit',
    pattern     TEXT        NOT NULL,
    action      TEXT        NOT NULL DEFAULT 'block',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    priority    INTEGER     NOT NULL DEFAULT 100,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT waf_rules_kind_ok CHECK (
        kind IN ('rate_limit', 'block_ua', 'block_ip', 'custom')
    ),
    CONSTRAINT waf_rules_action_ok CHECK (
        action IN ('block', 'challenge', 'log')
    )
);

CREATE INDEX waf_rules_server_idx ON waf_rules (server_id, priority);
