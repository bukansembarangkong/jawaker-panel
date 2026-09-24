-- Phase 17: Production hardening
-- system_health_log: records startup health checks and readiness events
-- upgrade_history: tracks migration runs for upgrade compatibility auditing
-- runbook_events: incident/recovery events for runbook validation

BEGIN;

-- system_health_log: startup and scheduled health check events
CREATE TABLE system_health_log (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    check_name   TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('ok', 'degraded', 'failed')),
    message      TEXT NOT NULL DEFAULT '',
    details      JSONB NOT NULL DEFAULT '{}',
    duration_ms  INT  NOT NULL DEFAULT 0,
    checked_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- upgrade_history: records each migration run for compatibility auditing
CREATE TABLE upgrade_history (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    migration_name  TEXT NOT NULL,
    from_version    TEXT NOT NULL DEFAULT '',
    to_version      TEXT NOT NULL DEFAULT '',
    applied_by      TEXT NOT NULL DEFAULT 'system',
    status          TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok', 'failed', 'rolled_back')),
    duration_ms     INT  NOT NULL DEFAULT 0,
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- runbook_events: record of incident/recovery drill outcomes for runbook validation
CREATE TABLE runbook_events (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    runbook_name TEXT NOT NULL,
    event_type   TEXT NOT NULL CHECK (event_type IN ('drill', 'incident', 'recovery', 'test')),
    outcome      TEXT NOT NULL CHECK (outcome IN ('pass', 'fail', 'partial')),
    performed_by TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    duration_min INT  NOT NULL DEFAULT 0,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_health_log_check_name ON system_health_log(check_name);
CREATE INDEX idx_health_log_checked_at ON system_health_log(checked_at DESC);
CREATE INDEX idx_upgrade_history_migration ON upgrade_history(migration_name);
CREATE INDEX idx_runbook_events_runbook ON runbook_events(runbook_name);
CREATE INDEX idx_runbook_events_occurred ON runbook_events(occurred_at DESC);

COMMIT;
