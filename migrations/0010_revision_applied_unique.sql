-- 0010_revision_applied_unique.sql — one applied revision per resource.
--
-- API.md s12 requires stale updates to be REJECTED rather than silently
-- overwriting a concurrent edit. An application-level "read the current
-- revision, compare, then write" check cannot provide that: two requests can
-- both read the same base and both proceed.
--
-- This partial unique index makes the invariant a database fact. Applying a
-- revision must first move the currently applied one to 'superseded' and then
-- mark the new one 'applied', in one transaction. Two concurrent applies for
-- the same resource therefore collide on the index, and exactly one wins — the
-- loser gets a conflict it can report as a stale base, which is the truth.
--
-- Scoped to state = 'applied' so history is unaffected: superseded, failed,
-- rolled_back, and draft revisions accumulate freely.

CREATE UNIQUE INDEX revisions_one_applied_per_resource_idx
    ON revisions (resource_type, resource_id)
    WHERE state = 'applied';
