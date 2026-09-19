# Contributing to JAWAKER

## Branching

- `main` is protected and always releasable.
- Use short-lived feature/fix branches; avoid long-lived divergence.
- Release tags are produced by CI after all gates pass.

## Commit style

Conventional commits with scopes:

```text
feat(api): add idempotent site creation
fix(agent): reject unsafe symlink escape
perf(metrics): reduce idle collection frequency
test(backup): add corrupted archive restore regression
```

A commit message never substitutes for in-product audit/revision history.

## Pull requests

Every PR description covers:

1. problem/requirement;
2. approach;
3. security impact;
4. resource/performance impact;
5. migrations (if any);
6. test evidence;
7. rollback/recovery impact;
8. screenshots for UI changes where useful.

## Review focus

Extra scrutiny applies to changes touching: auth/RBAC, node-agent privilege,
secrets, firewall/network, backup/restore, updater, migrations, module
permissions, and arbitrary file/process operations.

## Tests

- Run relevant checks before merge; never skip a failing test without
  documented review.
- Every reproducible bug fix ships with a regression test.

## Migrations

Released migrations are immutable. Never edit an applied migration file —
add a new one. The runner enforces this with checksums.

## Dependencies

New dependency PRs must state: why it is needed, alternatives considered,
maintenance/security health, size/resource effect, license compatibility, and
transitive risk.

## Security reports

Do not file public issues containing exploitable unpatched vulnerability
details. Use the private security reporting route (see repository security
policy).
