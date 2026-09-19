-- 0005_jobs.sql — durable job engine.
--
-- Baseline implementation uses PostgreSQL tables + row locks + LISTEN/NOTIFY
-- with a polling fallback (ADR-029). No external broker is required, so a
-- small installation stays lightweight.
--
-- Correctness requirements this schema must satisfy (ARCHITECTURE.md s3.5):
--   * persisted steps with independent status;
--   * leases with expiry so a crashed worker's job is recovered, not lost;
--   * bounded retry with backoff;
--   * cancellation that a running worker observes;
--   * idempotent enqueue via a caller-supplied key;
--   * per-resource locks so two jobs cannot mutate one resource at once.

CREATE TABLE jobs (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Job type key, e.g. "site.create", "backup.run", "panel.update".
    type              text NOT NULL,
    -- Owning scope. server_id/project_id are nullable because some jobs are
    -- installation-wide (e.g. "panel.update").
    server_id         uuid,
    project_id        uuid,
    -- Idempotency: caller-supplied key scoped by actor+type so a retried HTTP
    -- request cannot enqueue the same work twice (DATABASE.md s11).
    idempotency_key   text,
    idempotency_scope text,
    -- Higher number runs first within the same resource.
    priority          integer NOT NULL DEFAULT 100,
    -- queued | leased | running | succeeded | failed | canceled | dead_letter
    state             text NOT NULL DEFAULT 'queued'
                      CHECK (state IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'canceled', 'dead_letter')),
    -- Durable progress reporting for the UI (DESIGN_SYSTEM.md s15).
    progress_current  integer NOT NULL DEFAULT 0,
    progress_total    integer,
    current_step      text,
    -- Who asked for this job (audit + notification routing).
    requested_by_type text NOT NULL DEFAULT 'system'
                      CHECK (requested_by_type IN ('user', 'api_token', 'service', 'system', 'ai')),
    requested_by_id   uuid,
    payload           jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Lease: a worker holds the job for lease_expires_at. If it dies, another
    -- worker reclaims after expiry. This is the crash-recovery mechanism.
    lease_owner       text,
    lease_expires_at  timestamptz,
    attempt_count     integer NOT NULL DEFAULT 0,
    max_attempts      integer NOT NULL DEFAULT 3,
    -- Retry scheduling with exponential backoff.
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    -- Cancellation is cooperative: the request is recorded and the worker is
    -- expected to observe it at the next step boundary.
    cancel_requested_at timestamptz,
    cancel_requested_by uuid,
    -- Terminal outcome.
    error_code        text,
    error_summary     text,
    -- Dead-letter handling: set when attempts are exhausted.
    dead_lettered_at  timestamptz,
    -- Correlation with the HTTP request that created the job.
    request_id        text,
    -- Retention: finished jobs are pruned by a scheduled cleanup job.
    created_at        timestamptz NOT NULL DEFAULT now(),
    started_at        timestamptz,
    finished_at       timestamptz
);

-- Claim query path: find runnable jobs for a worker, oldest-first among the
-- highest priority. Partial index keeps it small (finished jobs excluded).
CREATE INDEX jobs_claim_idx
    ON jobs (priority DESC, next_attempt_at ASC)
    WHERE state IN ('queued', 'leased');

-- Recovery query path: find expired leases.
CREATE INDEX jobs_lease_expiry_idx
    ON jobs (lease_expires_at)
    WHERE state IN ('leased', 'running');

CREATE INDEX jobs_resource_idx ON jobs (server_id, project_id, state);
CREATE INDEX jobs_request_idx ON jobs (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX jobs_finished_idx ON jobs (finished_at) WHERE finished_at IS NOT NULL;

-- Idempotency must be enforced by the database so concurrent retries cannot
-- both insert (DATABASE.md s11).
CREATE UNIQUE INDEX jobs_idempotency_idx
    ON jobs (idempotency_scope, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Per-resource mutual exclusion: only one active job may hold a given lock
-- key (e.g. "site:<id>" or "server:<id>:firewall"). A partial unique index
-- gives us this guarantee without an application-level lock table.
CREATE TABLE job_resource_locks (
    lock_key          text PRIMARY KEY,
    job_id            uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    acquired_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX job_resource_locks_job_idx ON job_resource_locks (job_id);

-- Steps make progress durable and resumable at step granularity.
CREATE TABLE job_steps (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id            uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    -- Execution order within the job.
    step_index        integer NOT NULL,
    name              text NOT NULL,
    -- pending | running | succeeded | failed | skipped | canceled
    state             text NOT NULL DEFAULT 'pending'
                      CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'skipped', 'canceled')),
    -- Structured output. Bounded by the application: large output belongs in
    -- log storage, not in a row (DATABASE.md s8).
    output            jsonb,
    error_code        text,
    error_summary     text,
    started_at        timestamptz,
    finished_at       timestamptz,
    attempt           integer NOT NULL DEFAULT 1,
    UNIQUE (job_id, step_index)
);

CREATE INDEX job_steps_job_idx ON job_steps (job_id, step_index);

-- Attempt history: one row per execution attempt, for diagnostics and to
-- detect flapping jobs that keep failing and retrying.
CREATE TABLE job_attempts (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id            uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    attempt           integer NOT NULL,
    worker            text NOT NULL,
    outcome           text NOT NULL
                      CHECK (outcome IN ('leased', 'succeeded', 'failed', 'lost_lease', 'canceled')),
    error_code        text,
    error_summary     text,
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    UNIQUE (job_id, attempt)
);

CREATE INDEX job_attempts_job_idx ON job_attempts (job_id, attempt);
