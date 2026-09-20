# Architecture decisions

Recorded choices that shape more than one file, so a future reader can tell a
decision from an accident. Each entry states the decision, what forced it, and
what would change it.

The planning pack in `agent-md/` holds its own `DECISIONS.md`. That pack is
local-only and ignored by Git, so it is not reachable from a clone; this file is
the tracked log, and entries here are what a pull request reviewer can actually
read. Where the two differ, this file wins for anything in the repository.

---

## D-001 — Nginx site configs live in a JAWAKER-owned directory, attached once through the revision pipeline

**Decision.** Generated site configs are written to
`/etc/nginx/jawaker/sites-enabled/<project-slug>--<site-slug>.conf`. The host
`nginx.conf` gets exactly one added line,
`include /etc/nginx/jawaker/sites-enabled/*.conf;`, inserted by a separate
one-time **attach** step that runs through the same candidate → validate →
apply pipeline as every other config change.

**What forced it.** Nothing in `agent-md` specifies a layout, and the obvious
alternative — write into `conf.d/` and assume `nginx.conf` already includes it —
fails **silently** on any host whose `nginx.conf` does not. A site config that is
written, validated and "applied" but never included serves nothing, and every
check along the way reported success. That is the precise failure mode the whole
pipeline exists to prevent, so it cannot be assumed away.

Owning the directory also means the blast radius is stated rather than
inferred: a descriptor's `Scope.FilesystemWrite` names
`/etc/nginx/jawaker/sites-enabled` and nothing else. Writing into `conf.d`
would put JAWAKER's files beside whatever else lives there, and "this operation
may write to `/etc/nginx/conf.d`" is a much larger claim than it sounds like.

**Consequences.** The attach step must be idempotent (a second run is a no-op,
not a second include line), must be revertible, and must fail loudly rather than
skip when `nginx.conf` cannot be parsed. The filename carries both slugs so two
projects can each have a site called `www` without colliding on disk — the
database uniqueness for slugs is per-project
(`migrations/0014_projects_sites.sql`, `sites_slug_unique_idx`), so the filename
has to disambiguate what the schema deliberately does not.

**What would change it.** A supported installation path that guarantees the
include line exists would make the attach step unnecessary. It does not exist
yet, and inventing one is a later phase.

---

## D-002 — One Unix user per project; site roots under a project-owned tree

**Decision.** Each project gets one Unix user, `jw-<project-slug>`, and one
group of the same name. Site roots are
`/var/www/jawaker/<project-uuid>/<site-slug>/`, owned by that user and group,
mode `0750`. The nginx worker reads through the shared group.

**What forced it.** PRD.md §17.3 requires "project root isolation" and
"ownership enforcement", and names "jailed SFTP" and "per-project SFTP users".
A single shared user cannot satisfy any of those: with one user, every site's
files are mutually readable by every process running as that user, and there is
no boundary for an SFTP jail to confine.

The path carries the project **uuid**, not the slug. A slug is human-chosen and
mutable; renaming a project must not move files on disk, and a slug must never
be the only thing separating two tenants' directories
(`DATABASE.md` §4: opaque IDs are not security boundaries, and human-friendly
names are uniqued in their own scope — neither of which means a name is a
barrier).

**Consequences.** Site creation gains a privileged step that creates a system
user. That step is typed and scoped, not a shell string, per the rule that no
generic remote execution exists
(`AGENTS.md` §3, `SECURITY.md` §7, ADR-030). Deleting a project must stop
removing its config and files before it can remove the user, because a user with
files still owned by it cannot be deleted cleanly — which is one reason the
delete workflow is a grace-period state machine rather than a `DELETE`.

**What would change it.** Deferring per-project users to the phase that ships
SFTP would be defensible, but it would make the Phase 3 isolation tests
(`IMPLEMENTATION_PLAN.md` L90) assert something weaker than the spec requires,
and the file layout above would have to be migrated later — moving files under a
live web server is a worse operation than creating the user now.

---

## D-003 — A site runs on exactly one server

**Decision.** `sites.server_id` is `NOT NULL` and single-valued.

**What forced it.** `DATABASE.md` §6 requires an unambiguous ownership chain
and forbids authorization queries that depend on inferred ownership. A site
served from several nodes has no single node to validate against, no single
config file to roll back, and no single health check to trust — every one of
those becomes "which node?" before it can be answered.

**Consequences.** Multi-node distribution is a later-phase concern and will
likely be modelled as a separate placement table rather than by relaxing this
column. `ON DELETE RESTRICT` on `server_id` means removing a server from the
fleet requires moving or deleting its sites first, which is the moment an
operator should be forced to think about it.

**What would change it.** Load balancing or failover across nodes. Neither is in
Phase 3 scope.

---

## D-004 — `sites.state` follows the four-state lifecycle; `servers.status` keeps its three-state set

**Decision.** `projects` and `sites` use
`active | suspended | pending_delete | deleted`. `servers` keeps the
`pending | active | suspended | deleted` set that `migrations/0012` gave it, and
is **not** retrofitted with `pending_delete`.

**What forced it.** `DATABASE.md` §7 names the four-state lifecycle, and the
safe-delete workflow (`IMPLEMENTATION_PLAN.md` L84) needs a distinct
"deletion requested but still recoverable" state that is neither `active` nor
`deleted`. `servers` has no such workflow in Phase 2, and `0012` is released.

**Consequences.** The divergence is real and deliberate. Two migrations must not
be edited to reconcile it — `docs/contributing.md` and `DATABASE.md` §13 both
forbid changing a released migration, so reconciliation would mean a new
migration whose only job is cosmetic. When servers gain a delete workflow, it
should arrive with `pending_delete` in that migration.

Note also the column-name divergence: `servers.status` versus `sites.state`. Same
reason, same resolution.

**What would change it.** A server delete workflow with a grace period.

---

## D-005 — Site logs are read from the node on demand, never stored in PostgreSQL

**Decision.** The `site.log.read` operation returns a bounded, redacted tail
read from the node at request time. No log content is copied into the
control-plane database.

**What forced it.** `ARCHITECTURE.md` §3.3 states large logs are not stored as
PostgreSQL blobs, and `DATABASE.md` §2 says the control plane stores "metadata
and state, not large backup/log blobs". A log column would be unbounded growth
in the one table that every other subsystem depends on, and `PRD.md` §42 forbids
any subsystem growing disk usage without a defined upper bound.

**Consequences.** Log search across time requires either node-side retention or
the log-shipping phase, which is later. Phase 3 ships tail and bounded read, not
full-text search over history.

**What would change it.** The log pipeline phase, which is where indexing and
retention belong.

---

## D-006 — A new project-scoped permission rather than re-scoping `logs.read`

**Decision.** `migrations/0015_site_logs_permission.sql` adds
`site.logs.read` (project-scoped). `logs.read` keeps its server scope.

**What forced it.** See the header comment of that migration. The short version:
widening `logs.read` would silently change the meaning of every existing grant,
and a migration that re-scopes an authorization key is indistinguishable from
one that widened access by accident.

**Consequences.** Two permissions cover logs, and a route must pick the right
one. Site log routes use `site.logs.read`; host-level log routes use
`logs.read`. A route that picks wrong fails closed for a customer rather than
open, because the project-scoped grant cannot satisfy a server-scoped check.

**What would change it.** Nothing foreseeable. If the two ever need merging, it
must be a new key plus an explicit backfill, not a scope change.

---

## D-007 — Nginx and PHP logic ships as internal packages, not as module manifests

**Decision.** Phase 3 implements the nginx config generator and the PHP-FPM
runtime discovery inside `internal/`, as ordinary Go packages. It does not
introduce the module manifest schema or a module loader.

**What forced it.** `PRD.md` §8.2 lists Nginx as a module, and `MODULES.md`
defines a manifest with a *separate* machine-permission vocabulary
(`service.manage:nginx`, `filesystem.write:<scope>`, `network.listen:<port>`)
from the dotted human RBAC catalog in `migrations/0007`. `SECURITY.md` §5 states
the two namespaces are deliberately separate. Building both in one phase would
mean designing the module platform under time pressure from the web-hosting work
that depends on it.

**Consequences.** The nginx generator must be written so it can be lifted behind
a module boundary later: its inputs are typed, its permissions are the human RBAC
keys, and its node operations are registry descriptors rather than in-process
calls. `MODULES.md` L47 requires the manifest schema be "versioned and
validated", which is a design task of its own.

**What would change it.** The phase that introduces module installation, at which
point the manifest schema needs to exist and the generator moves behind it.

---

## D-008 — HTTP-01 uses `golang.org/x/crypto/acme`, adding no dependency

**Decision.** ACME issuance uses `golang.org/x/crypto/acme`, already a direct
dependency of the module (`go.mod`).

**What forced it.** `AGENTS.md` §5 requires a purpose, alternatives, security
posture, maintenance and removal-cost case for any new dependency, and §4
forbids new infrastructure dependencies when the existing stack suffices.
`x/crypto/acme` provides `Discover` with a caller-set `DirectoryURL` — which is
what `PRD.md` §15.1's "multiple ACME CAs and custom ACME endpoints" needs — plus
`HTTP01ChallengePath`, `HTTP01ChallengeResponse`, `Accept`,
`WaitAuthorization`, `CreateOrderCert` and `RevokeCert`.

**Consequences.** No vendored ACME client, no new supply-chain surface, and
renewal logic is written against a standard library-adjacent API rather than a
third-party wrapper whose abstractions would have to be unwound to implement the
six-step safe-renewal order in `PRD.md` §15.4.

**What would change it.** A requirement `x/crypto/acme` cannot express, such as
an ACME profile or extension outside RFC 8555.

---

## D-009 — Error codes follow `apierr`'s lowercase snake_case, not the PRD's uppercase example

**Decision.** New codes are lowercase snake_case, e.g.
`config_validation_failed`.

**What forced it.** `PRD.md` §38.2 shows `"code": "CONFIG_VALIDATION_FAILED"`
while `API.md` §8 shows `config_validation_failed`. Every code already shipped in
`internal/apierr/apierr.go` is lowercase snake_case, and a client that branches
on the code string cannot handle both spellings of one condition.

**Consequences.** Documented examples that quote the uppercase form are
illustrations of the field, not of its value. `AGENTS.md` §2 requires the
conflict be recorded rather than silently resolved, which is what this entry is.

**What would change it.** Nothing. Picking the other spelling now would be a
breaking change to every existing client.
