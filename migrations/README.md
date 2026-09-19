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

## Status

**Empty by design.** The first production schema (identity/RBAC/audit/jobs)
arrives with Phase 1. Placeholder tables are not created ahead of the code
that owns them.
