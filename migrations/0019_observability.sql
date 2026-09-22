-- 0019_observability.sql — Phase 7 Observability and incidents:
-- bounded metric samples, alert rules, alert incidents, scheduled reports.
--
-- Scope: OBSERVABILITY.md §3 (Metrics), §5 (Incidents), §6 (Alerts),
-- §8 (Scheduled reports), §9 (Disk safety), IMPLEMENTATION_PLAN.md Phase 7.
--
-- Baseline metrics are host-level only (cpu/mem/disk/load). Web, runtime,
-- database, and container metrics arrive with their own phases.

-- Metric samples: one row per (server, metric) observation.
-- Retention is enforced by the evaluator worker (PruneSamples), never by the
-- schema — the schema only bounds what a single row can hold.
CREATE TABLE metric_samples (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id    uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    metric       text NOT NULL
                 CHECK (metric IN ('cpu_pct', 'mem_pct', 'disk_pct', 'load1')),
    -- percentages are 0..100; load1 is unbounded but never negative
    value        double precision NOT NULL CHECK (value >= 0),
    observed_at  timestamptz NOT NULL
);

-- The evaluator and the metrics API both read newest-first per server+metric.
CREATE INDEX metric_samples_lookup_idx
    ON metric_samples (server_id, metric, observed_at DESC);

-- Alert rules: one threshold condition on one metric for one server.
CREATE TABLE alert_rules (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id         uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    name              text NOT NULL,
    metric            text NOT NULL
                      CHECK (metric IN ('cpu_pct', 'mem_pct', 'disk_pct', 'load1')),
    -- gt: fires when value stays above threshold; lt: below
    comparator        text NOT NULL CHECK (comparator IN ('gt', 'lt')),
    threshold         double precision NOT NULL,
    -- condition must hold for this long before an incident opens
    duration_seconds  int NOT NULL DEFAULT 300 CHECK (duration_seconds BETWEEN 60 AND 86400),
    severity          text NOT NULL DEFAULT 'warning'
                      CHECK (severity IN ('info', 'warning', 'critical')),
    enabled           boolean NOT NULL DEFAULT true,
    state             text NOT NULL DEFAULT 'active'
                      CHECK (state IN ('active', 'suspended')),
    created_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT alert_rules_name_present CHECK (btrim(name) <> '')
);

CREATE INDEX alert_rules_server_idx ON alert_rules (server_id) WHERE enabled AND state = 'active';

-- Alert incidents: one OPEN incident per rule (dedup). Recovery closes it.
CREATE TABLE alert_incidents (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id      uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
    server_id    uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    state        text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved')),
    -- dedup key identifies the CONDITION, e.g. "rule:<rule_id>"
    dedup_key    text NOT NULL,
    opened_at    timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz,
    -- when the firing notification was published; NULL until delivery is attempted
    notified_at  timestamptz,

    CONSTRAINT alert_incidents_resolved_shape CHECK (
        (state = 'resolved') = (resolved_at IS NOT NULL)
    )
);

-- One open incident per condition. A second firing of the same rule finds the
-- existing row instead of opening another (OBSERVABILITY.md §6 dedup).
CREATE UNIQUE INDEX alert_incidents_open_dedup_idx
    ON alert_incidents (dedup_key) WHERE state = 'open';
CREATE INDEX alert_incidents_server_idx ON alert_incidents (server_id, opened_at DESC);

-- Report schedules: periodic summary notifications.
CREATE TABLE report_schedules (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL,
    cadence      text NOT NULL CHECK (cadence IN ('daily', 'weekly', 'monthly')),
    next_run_at  timestamptz NOT NULL,
    enabled      boolean NOT NULL DEFAULT true,
    last_run_at  timestamptz,
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT report_schedules_name_present CHECK (btrim(name) <> '')
);

CREATE INDEX report_schedules_due_idx ON report_schedules (next_run_at)
    WHERE enabled;
