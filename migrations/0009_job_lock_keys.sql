-- 0009_job_lock_keys.sql — persist a job's DECLARED resource requirements.
--
-- 0005 introduced job_resource_locks, which records locks a job CURRENTLY
-- HOLDS (acquired at claim time, released at terminal state). But a worker
-- claiming a job in a different process, after a restart, has no in-memory copy
-- of which locks that job needs. The declared intent must therefore be durable
-- too, or per-resource exclusion cannot survive a controller restart — which is
-- exactly the Phase 1 gate ("restart does not lose queued/running jobs").
--
-- These are two distinct facts, not a duplication:
--   jobs.lock_keys        = what the job NEEDS (intent, immutable after enqueue)
--   job_resource_locks    = what the job HOLDS right now (runtime state)
-- A claim query excludes candidates whose declared keys collide with a lock
-- another job holds, then inserts the rows into job_resource_locks atomically.

ALTER TABLE jobs
    ADD COLUMN lock_keys text[] NOT NULL DEFAULT '{}';

-- Empty keys mean "no exclusion needed", which is the overwhelmingly common
-- case; a partial index keeps the claim query's lock-collision check small.
CREATE INDEX jobs_lock_keys_idx ON jobs USING GIN (lock_keys)
    WHERE lock_keys <> '{}';
