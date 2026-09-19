-- 0004_audit_revisions.sql — immutable change history.
--
-- Two distinct concerns live here (DATABASE.md s9, s10):
--   * audit_events  — append-only record of "who did what, to what, with what
--                     result". Never updated by normal application code.
--   * revisions     — the intended-vs-actual configuration change record that
--                     every meaningful config mutation must produce
--                     (PRD s24.2, rule 17).
--
-- Neither table stores secret values. Revisions store references and hashes
-- only (SECURITY.md s8, rule 18).

CREATE TABLE audit_events (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Monotonic sequence for stable ordering and tamper-evident paging. A
    -- bigserial is intentional here: it is never exposed as a security
    -- boundary, only used for ordering (DATABASE.md s4).
    seq               bigserial NOT NULL,
    -- 'user' | 'api_token' | 'service' | 'system' | 'ai'
    actor_type        text NOT NULL
                      CHECK (actor_type IN ('user', 'api_token', 'service', 'system', 'ai')),
    actor_id          uuid,
    -- Set when a privileged user acts on behalf of another (PRD s5.4).
    impersonator_id   uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Canonical action key, e.g. "site.create", "session.revoke".
    action            text NOT NULL,
    resource_type     text NOT NULL,
    resource_id       text,
    -- Correlation across logs, jobs, revisions, and incidents (API.md s6).
    request_id        text,
    job_id            uuid,
    revision_id       uuid,
    -- 'success' | 'failure' | 'denied'
    result            text NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    -- Stable machine code for failures (matches apierr codes).
    error_code        text,
    -- Human-readable reason; required for impersonation and denials.
    reason            text,
    -- Non-secret structured context. Never contains credentials.
    context           jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Source metadata; nullable because some events are system-originated.
    source_ip         inet,
    user_agent        text,
    occurred_at       timestamptz NOT NULL DEFAULT now()
);

-- Audit is append-only. A trigger makes accidental UPDATE/DELETE a database
-- error rather than a silent history rewrite, so a bug in application code
-- cannot quietly edit the trail (DATABASE.md s10).
CREATE OR REPLACE FUNCTION audit_events_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (attempted %)', TG_OP
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

CREATE INDEX audit_events_recent_idx ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX audit_events_resource_idx ON audit_events (resource_type, resource_id, occurred_at DESC);
CREATE INDEX audit_events_request_idx ON audit_events (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX audit_events_job_idx ON audit_events (job_id) WHERE job_id IS NOT NULL;
CREATE INDEX audit_events_denied_idx ON audit_events (occurred_at DESC) WHERE result <> 'success';

-- A revision is the immutable record of an intended configuration change.
CREATE TABLE revisions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Changed resource. resource_id is text to accommodate module-defined
    -- resource kinds without a schema change per module.
    resource_type     text NOT NULL,
    resource_id       text NOT NULL,
    -- Identity of the actor that requested the change.
    actor_type        text NOT NULL
                      CHECK (actor_type IN ('user', 'api_token', 'service', 'system', 'ai')),
    actor_id          uuid,
    -- Optimistic concurrency: the revision this change was based on. Used to
    -- reject stale updates instead of silently overwriting concurrent edits
    -- (API.md s12).
    base_revision_id  uuid REFERENCES revisions (id) ON DELETE SET NULL,
    -- Normalized candidate payload (secret values replaced by references).
    candidate         jsonb NOT NULL,
    -- Normalized previous payload used to render the diff.
    previous          jsonb,
    -- SHA-256 of the canonicalized candidate; lets drift detection compare
    -- cheaply without re-diffing large documents.
    candidate_hash    text NOT NULL,
    -- Lifecycle: draft -> validated -> applied -> superseded/failed/rolled_back
    state             text NOT NULL DEFAULT 'draft'
                      CHECK (state IN ('draft', 'validated', 'applied', 'failed', 'rolled_back', 'superseded')),
    validation_result jsonb,
    -- Correlated job that performed the apply (durable job system).
    apply_job_id      uuid,
    -- Result of the post-apply health check.
    health_result     jsonb,
    -- Recovery metadata: what to restore and how.
    rollback_ref      jsonb,
    -- Git synchronization state (PRD s24.3: GitHub must never block local work).
    git_sync_state    text NOT NULL DEFAULT 'pending'
                      CHECK (git_sync_state IN ('pending', 'synced', 'failed', 'not_required')),
    git_commit_sha    text,
    git_sync_error    text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    applied_at        timestamptz
);

-- Revisions are history: forbid in-place edits of the substance, while still
-- allowing the state/result columns to be filled in as the change progresses.
CREATE OR REPLACE FUNCTION revisions_reject_immutable_changes() RETURNS trigger AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.resource_type <> OLD.resource_type
       OR NEW.resource_id <> OLD.resource_id
       OR NEW.candidate <> OLD.candidate
       OR NEW.candidate_hash <> OLD.candidate_hash
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'revision substance is immutable; create a new revision instead'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER revisions_no_substance_edit
    BEFORE UPDATE ON revisions
    FOR EACH ROW EXECUTE FUNCTION revisions_reject_immutable_changes();

CREATE INDEX revisions_resource_idx ON revisions (resource_type, resource_id, created_at DESC);
CREATE INDEX revisions_base_idx ON revisions (base_revision_id) WHERE base_revision_id IS NOT NULL;
CREATE INDEX revisions_pending_git_idx ON revisions (created_at) WHERE git_sync_state = 'pending';
