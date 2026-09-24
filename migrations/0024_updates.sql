-- 0024_updates.sql: Update platform — release discovery, snapshots, update jobs, canary rollouts, module updates
-- Phase 12

-- Available releases discovered from GitHub
CREATE TABLE update_releases (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel       TEXT NOT NULL CHECK (channel IN ('stable', 'beta', 'edge')),
    version       TEXT NOT NULL,
    tag           TEXT NOT NULL,
    notes         TEXT NOT NULL DEFAULT '',
    artifact_url  TEXT NOT NULL,
    checksum_url  TEXT NOT NULL,
    signature_url TEXT NOT NULL,
    published_at  TIMESTAMPTZ NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    compatible    BOOLEAN,                    -- NULL = not yet checked
    UNIQUE (channel, version)
);

-- Snapshot/recovery points taken before applying an update
CREATE TABLE update_snapshots (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    release_id   UUID NOT NULL REFERENCES update_releases(id),
    state        TEXT NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'running', 'ready', 'failed', 'restored')),
    manifest     JSONB NOT NULL DEFAULT '{}', -- recorded paths/checksums
    snapshot_at  TIMESTAMPTZ,
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Update jobs (one per apply attempt)
CREATE TABLE update_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    release_id    UUID NOT NULL REFERENCES update_releases(id),
    snapshot_id   UUID REFERENCES update_snapshots(id),
    state         TEXT NOT NULL DEFAULT 'pending'
                      CHECK (state IN ('pending', 'preflight', 'downloading', 'verifying',
                                       'applying', 'done', 'failed', 'rolled_back')),
    triggered_by  UUID NOT NULL REFERENCES users(id),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fleet canary rollout: tracks per-server update state
CREATE TABLE canary_rollouts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id       UUID NOT NULL REFERENCES update_jobs(id),
    server_id    UUID NOT NULL REFERENCES servers(id),
    state        TEXT NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'applying', 'done', 'failed', 'paused')),
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    UNIQUE (job_id, server_id)
);

-- Module updates: per-module version tracking
CREATE TABLE module_updates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_name  TEXT NOT NULL,
    current_ver  TEXT NOT NULL,
    latest_ver   TEXT,
    state        TEXT NOT NULL DEFAULT 'idle'
                     CHECK (state IN ('idle', 'updating', 'done', 'failed')),
    last_checked TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (module_name)
);

-- Indexes
CREATE INDEX update_releases_channel_idx ON update_releases (channel, published_at DESC);
CREATE INDEX update_jobs_state_idx       ON update_jobs (state, created_at DESC);
CREATE INDEX canary_rollouts_job_idx     ON canary_rollouts (job_id, state);
