-- 0018_backup_plans.sql — Phase 6 Backup and disaster recovery baseline:
-- backup plans, backup runs/manifests, and secure expiring download links.
--
-- Scope: BACKUP_RECOVERY.md §4 (Backup plan), §5 (Manifest), §6 (Integrity),
-- §7 (Restore), §10 (Expiring links), §11 (Retention),
-- PRD.md §18 (Backup & Disaster Recovery), IMPLEMENTATION_PLAN.md Phase 6.

-- Backup plans: policy defining scope, schedule, destination, and retention.
CREATE TABLE backup_plans (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id              uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    server_id               uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    name                    text NOT NULL,
    slug                    text NOT NULL,
    -- project | site | database (BACKUP_RECOVERY.md §2)
    scope_type              text NOT NULL
                            CHECK (scope_type IN ('project', 'site', 'database')),
    -- optional target resource (e.g. site_id or database_id), NULL for full project
    scope_id                uuid,
    -- local | s3 (BACKUP_RECOVERY.md §3)
    destination_type        text NOT NULL DEFAULT 'local'
                            CHECK (destination_type IN ('local', 's3')),
    -- bucket, endpoint, region, prefix metadata
    destination_config      jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- secret:// reference to credentials (access_key/secret_key)
    destination_config_ref  text NOT NULL DEFAULT '',
    -- secret:// reference to encryption key
    encryption_key_ref      text NOT NULL DEFAULT '',
    -- cron expression (e.g. "0 2 * * *" for daily 02:00 UTC), empty for manual only
    schedule_cron           text NOT NULL DEFAULT '',
    next_run_at             timestamptz,
    enabled                 boolean NOT NULL DEFAULT true,
    retention_count         int NOT NULL DEFAULT 7 CHECK (retention_count >= 1),
    retention_days          int NOT NULL DEFAULT 30 CHECK (retention_days >= 1),
    -- active | suspended | pending_delete | deleted
    state                   text NOT NULL DEFAULT 'active'
                            CHECK (state IN ('active', 'suspended', 'pending_delete', 'deleted')),

    created_by              uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    delete_after            timestamptz,
    deleted_at              timestamptz,

    CONSTRAINT backup_plans_slug_present    CHECK (btrim(slug) <> ''),
    CONSTRAINT backup_plans_name_present    CHECK (btrim(name) <> ''),
    CONSTRAINT backup_plans_slug_safe       CHECK (slug ~ '^[a-z0-9]([a-z0-9_]*[a-z0-9])?$'),
    CONSTRAINT backup_plans_slug_length     CHECK (char_length(slug) BETWEEN 2 AND 48),
    CONSTRAINT backup_plans_deleted_shape   CHECK (
        (state = 'deleted') = (deleted_at IS NOT NULL)
    ),
    CONSTRAINT backup_plans_delete_after_shape CHECK (
        (state = 'pending_delete') = (delete_after IS NOT NULL)
    )
);

CREATE UNIQUE INDEX backup_plans_project_slug_idx ON backup_plans (project_id, slug)
    WHERE deleted_at IS NULL;
CREATE INDEX backup_plans_project_state_idx ON backup_plans (project_id, state);
CREATE INDEX backup_plans_next_run_idx ON backup_plans (next_run_at)
    WHERE enabled = true AND state = 'active' AND deleted_at IS NULL;

-- Backup runs: individual execution records and artifacts.
CREATE TABLE backup_runs (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id                 uuid REFERENCES backup_plans (id) ON DELETE SET NULL,
    project_id              uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    server_id               uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    trigger                 text NOT NULL CHECK (trigger IN ('manual', 'scheduled', 'pre_change')),
    state                   text NOT NULL DEFAULT 'queued'
                            CHECK (state IN ('queued', 'running', 'completed', 'failed')),
    archive_path            text NOT NULL DEFAULT '',
    archive_size_bytes      bigint NOT NULL DEFAULT 0 CHECK (archive_size_bytes >= 0),
    sha256                  text NOT NULL DEFAULT '',
    encryption_key_ref      text NOT NULL DEFAULT '',
    manifest                jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- unverified | verified | failed | expired (BACKUP_RECOVERY.md §6)
    verification_state      text NOT NULL DEFAULT 'unverified'
                            CHECK (verification_state IN ('unverified', 'verified', 'failed', 'expired')),
    job_id                  uuid REFERENCES jobs (id) ON DELETE SET NULL,
    requested_by_type       text NOT NULL DEFAULT 'system' CHECK (requested_by_type IN ('user', 'system')),
    requested_by_id         text NOT NULL DEFAULT '',
    idempotency_key         text,
    failed_reason           text NOT NULL DEFAULT '',
    created_at              timestamptz NOT NULL DEFAULT now(),
    started_at              timestamptz,
    completed_at            timestamptz
);

CREATE INDEX backup_runs_plan_idx ON backup_runs (plan_id, created_at DESC);
CREATE INDEX backup_runs_project_idx ON backup_runs (project_id, created_at DESC);
CREATE INDEX backup_runs_job_idx ON backup_runs (job_id) WHERE job_id IS NOT NULL;
CREATE UNIQUE INDEX backup_runs_idempotency_idx ON backup_runs (project_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Expiring download links: short-lived, single-use, authenticated links for archive download (BACKUP_RECOVERY.md §10).
CREATE TABLE backup_expiring_links (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id                  uuid NOT NULL REFERENCES backup_runs (id) ON DELETE CASCADE,
    project_id              uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    token_hash              text NOT NULL UNIQUE,
    expires_at              timestamptz NOT NULL,
    single_use              boolean NOT NULL DEFAULT true,
    used_at                 timestamptz,
    revoked_at              timestamptz,
    created_by              uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX backup_expiring_links_token_hash_idx ON backup_expiring_links (token_hash)
    WHERE revoked_at IS NULL AND used_at IS NULL;
