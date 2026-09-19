## Problem / requirement

<!-- Which requirement or defect does this change address? Link issues. -->

## Approach

<!-- What was done and why; alternatives considered for non-trivial choices. -->

## Security impact

<!-- Trust boundaries touched; authz/authn changes; secret handling; input validation. Write "none" explicitly when true. -->

## Resource / performance impact

<!-- Idle RAM/CPU, query patterns, bundle size, polling vs event-driven. -->

## Migrations

<!-- New migration files? Immutability respected? Expand/migrate/contract used where risky? -->

## Test evidence

<!-- Commands run + results. New tests added? Regression test for a bug fix? -->

## Rollback / recovery impact

<!-- What happens if this must be reverted after deploy? Any irreversible step? -->

## Screenshots

<!-- Required for UI changes. -->

---

### Checklist

- [ ] Server-side authorization enforced (not UI-only)
- [ ] Audit events where required
- [ ] Failure paths tested, not only happy path
- [ ] No secrets in code/logs/fixtures
- [ ] Migrations immutable and tested
- [ ] Docs updated for public-facing behavior
