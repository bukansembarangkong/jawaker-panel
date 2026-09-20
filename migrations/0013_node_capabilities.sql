-- 0013_node_capabilities.sql — capability inventory and heartbeat observations.
--
-- Scope: what a node REPORTS about itself (ARCHITECTURE.md §5: "Controller
-- stores intended configuration. Node reports observed state."). Everything
-- here is observation, never intent, and is therefore safe to overwrite and
-- safe to prune.
--
-- Why these are separate tables rather than columns on `servers`:
--
--   * `node_capabilities` is a SET, not a fixed shape. A node that gains
--     PostgreSQL support does not get a new column on servers; it gets a new
--     row. This is what keeps the schema from growing a column per module as
--     the module platform arrives in later phases.
--   * `node_heartbeats` is APPEND-ONLY time series. Overwriting `last_seen_at`
--     on servers answers "is it up now?" but cannot answer "was it up during
--     the outage?", which is the question an incident asks. Retention is
--     bounded by a scheduled cleanup job, not by an unbounded table.
--
-- Design notes:
--   * Capability rows are keyed by (server_id, kind, name) so re-reporting an
--     unchanged capability is an upsert rather than a duplicate. The node's
--     inventory is idempotent to report.
--   * `state` distinguishes a capability that WORKS from one the node knows
--     about but cannot use (missing binary, unsupported init system). Without
--     this the controller would infer support from presence alone, and a node
--     with no systemd would look like it could restart services.
--   * Heartbeats carry the observation timestamp from the NODE as well as the
--     receipt time. Clock skew between node and controller is a real
--     operational fact, and collapsing the two timestamps would hide it.

-- A capability the node has detected and can act on.
CREATE TABLE node_capabilities (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    -- Broad bucket, e.g. 'os', 'init', 'service', 'web', 'database'. Kept
    -- coarse and bounded so it can be filtered on without becoming a
    -- high-cardinality label (OBSERVABILITY.md §3).
    kind        text NOT NULL,
    -- Specific capability within the kind, e.g. 'systemd', 'nginx'.
    name        text NOT NULL,
    -- Detected version string, empty when not applicable.
    version     text NOT NULL DEFAULT '',
    -- available | degraded | unsupported
    --
    -- 'available' means the node verified it can use this, not merely that a
    -- file exists. 'unsupported' is the honest answer for a capability the
    -- node recognizes but cannot service on this host.
    state       text NOT NULL DEFAULT 'available'
                CHECK (state IN ('available', 'degraded', 'unsupported')),
    -- Structured evidence: detected paths, resolved program, reason for
    -- degradation. Non-secret by construction — this table is a report an
    -- operator reads, so it must never carry credentials.
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT node_capabilities_kind_present CHECK (btrim(kind) <> ''),
    CONSTRAINT node_capabilities_name_present CHECK (btrim(name) <> ''),
    CONSTRAINT node_capabilities_unique UNIQUE (server_id, kind, name)
);

CREATE INDEX node_capabilities_server_kind_idx ON node_capabilities (server_id, kind);

-- Append-only heartbeat observations.
CREATE TABLE node_heartbeats (
    id              bigserial PRIMARY KEY,
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    -- When the NODE says it observed this. Distinct from received_at on
    -- purpose: a node with a wrong clock is a real failure mode and the
    -- discrepancy is the evidence for it.
    observed_at     timestamptz NOT NULL,
    -- When the controller accepted it.
    received_at     timestamptz NOT NULL DEFAULT now(),
    uptime_seconds  bigint NOT NULL DEFAULT 0
                    CHECK (uptime_seconds >= 0),
    -- 1-minute load average, scaled by 1000 so it stays an integer. A float
    -- would be fine, but a scaled integer compares and aggregates without any
    -- application-side rounding decisions.
    load1_milli     integer NOT NULL DEFAULT 0
                    CHECK (load1_milli >= 0),
    mem_total_bytes bigint NOT NULL DEFAULT 0 CHECK (mem_total_bytes >= 0),
    mem_used_bytes  bigint NOT NULL DEFAULT 0 CHECK (mem_used_bytes >= 0),
    -- Agent-reported count of hosted workloads it is responsible for. The
    -- "node survives controller outage" gate is about these staying untouched,
    -- so the number is recorded alongside each observation to make a change
    -- visible in the time series.
    workload_count  integer NOT NULL DEFAULT 0
                    CHECK (workload_count >= 0),

    CONSTRAINT node_heartbeats_memory_shape CHECK (mem_used_bytes <= mem_total_bytes)
);

-- Time-series read path: newest-first per server. The DESC index is what makes
-- "last N heartbeats for this server" a bounded index scan.
CREATE INDEX node_heartbeats_server_observed_idx
    ON node_heartbeats (server_id, observed_at DESC);

-- Retention sweep path: delete by age without touching the per-server index.
CREATE INDEX node_heartbeats_received_idx ON node_heartbeats (received_at);
