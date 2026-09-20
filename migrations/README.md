# Control-plane SQL migrations

This directory holds the JAWAKER control-plane PostgreSQL migrations, embedded
into the controller binary at build time and applied by
`internal/db/migrate`.

## Rules

- File names: `NNNN_snake_case.sql` (4-digit zero-padded version prefix).
- Migrations are **immutable once released** — never edit an applied file;
  add a new migration. The runner verifies SHA-256 checksums and refuses to
  start on a mismatch.
- Forward-only. Binary rollback does not reverse schema changes; recovery
  relies on database backups (see DATABASE.md §13 — we do not claim rollback
  guarantees that are not technically true).
- Prefer expand/migrate/contract patterns for risky changes; avoid long
  exclusive locks.

## Index

| Version | Domain |
| --- | --- |
| `0001_init.sql` | Intentionally a no-op; the first real schema arrives in `0002`. |
| `0002_identity.sql` | users, password credentials, sessions, TOTP, recovery codes |
| `0003_rbac.sql` | permissions, roles, role_permissions, role_bindings |
| `0004_audit_revisions.sql` | audit_events (append-only), revisions (immutable) |
| `0005_jobs.sql` | jobs, job_resource_locks, job_steps, job_attempts |
| `0006_notifications.sql` | channels, routes, deliveries, reads |
| `0007_rbac_seed.sql` | the permission catalog and the nine built-in roles |
| `0008_secrets.sql` | secret_values (AEAD envelope + key version) |
| `0009_job_lock_keys.sql` | `jobs.lock_keys` |
| `0010_revision_applied_unique.sql` | one applied revision per resource |
| `0011_mfa_enrollment_lifecycle.sql` | splits the TOTP unique indexes by lifecycle state |
| `0012_node_enrollment.sql` | controller_identity, servers, enrollment_tokens, node_identities, node_certificates |
| `0013_node_capabilities.sql` | node_capabilities, node_heartbeats |
| `0014_projects_sites.sql` | projects, memberships, quotas, sites, site_domains, certificates, domain_certificates |
| `0015_site_logs_permission.sql` | the project-scoped `site.logs.read` permission |

Architecture-impacting choices recorded alongside these schemas live in
[docs/decisions.md](../docs/decisions.md).
