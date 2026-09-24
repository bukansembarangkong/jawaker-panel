-- Phase 14: Multi-server HA and advanced routing
-- server_pools: named groups of servers for load-balanced/HA ingress
-- pool_members: servers assigned to a pool with drain/active state
-- failover_events: log of detected failures and automated or manual responses
-- quorum_configs: per-pool quorum rules (min healthy, fencing policy)
-- drain_requests: tracks in-progress node drain operations

BEGIN;

-- server_pools: logical grouping of nodes for HA patterns
CREATE TABLE server_pools (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    project_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'active-passive'
                CHECK (mode IN ('active-passive', 'active-active', 'canary')),
    state       TEXT NOT NULL DEFAULT 'healthy'
                CHECK (state IN ('healthy', 'degraded', 'failed', 'draining')),
    min_healthy INT  NOT NULL DEFAULT 1 CHECK (min_healthy >= 1),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

-- pool_members: servers assigned to a pool
CREATE TABLE pool_members (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    pool_id     TEXT NOT NULL REFERENCES server_pools(id) ON DELETE CASCADE,
    server_id   TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member'
                CHECK (role IN ('primary', 'secondary', 'member', 'standby')),
    state       TEXT NOT NULL DEFAULT 'active'
                CHECK (state IN ('active', 'draining', 'drained', 'failed', 'offline')),
    weight      INT  NOT NULL DEFAULT 100 CHECK (weight BETWEEN 0 AND 1000),
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (pool_id, server_id)
);

-- drain_requests: track node drain lifecycle
CREATE TABLE drain_requests (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    pool_id      TEXT NOT NULL REFERENCES server_pools(id) ON DELETE CASCADE,
    server_id    TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending', 'draining', 'drained', 'cancelled', 'failed')),
    reason       TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- quorum_configs: fencing policy per pool
CREATE TABLE quorum_configs (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    pool_id         TEXT NOT NULL UNIQUE REFERENCES server_pools(id) ON DELETE CASCADE,
    min_votes       INT  NOT NULL DEFAULT 2 CHECK (min_votes >= 1),
    fencing_enabled BOOLEAN NOT NULL DEFAULT false,
    fencing_method  TEXT NOT NULL DEFAULT 'none'
                    CHECK (fencing_method IN ('none', 'power', 'network', 'stonith')),
    split_brain_policy TEXT NOT NULL DEFAULT 'pause'
                        CHECK (split_brain_policy IN ('pause', 'demote', 'shutdown')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- failover_events: log of HA state transitions
CREATE TABLE failover_events (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    pool_id       TEXT NOT NULL REFERENCES server_pools(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL
                  CHECK (event_type IN ('node_down', 'node_up', 'failover', 'failback', 'drain_start', 'drain_complete', 'quorum_lost', 'quorum_restored', 'drill')),
    server_id     TEXT,
    triggered_by  TEXT NOT NULL DEFAULT 'system',
    details       JSONB NOT NULL DEFAULT '{}',
    resolved      BOOLEAN NOT NULL DEFAULT false,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- failover_drills: scheduled or manual HA test runs
CREATE TABLE failover_drills (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    pool_id      TEXT NOT NULL REFERENCES server_pools(id) ON DELETE CASCADE,
    drill_type   TEXT NOT NULL DEFAULT 'manual'
                 CHECK (drill_type IN ('manual', 'scheduled')),
    state        TEXT NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending', 'running', 'passed', 'failed', 'cancelled')),
    initiated_by TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_log   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for common queries
CREATE INDEX idx_pool_members_pool_id   ON pool_members(pool_id);
CREATE INDEX idx_pool_members_server_id ON pool_members(server_id);
CREATE INDEX idx_failover_events_pool_id   ON failover_events(pool_id);
CREATE INDEX idx_failover_events_occurred  ON failover_events(occurred_at DESC);
CREATE INDEX idx_drain_requests_pool_id    ON drain_requests(pool_id);
CREATE INDEX idx_drain_requests_server_id  ON drain_requests(server_id);
CREATE INDEX idx_server_pools_project_id   ON server_pools(project_id);
CREATE INDEX idx_failover_drills_pool_id   ON failover_drills(pool_id);

COMMIT;
