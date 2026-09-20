-- 0015_site_logs_permission.sql — a project-scoped permission to read a site's
-- logs, and its grants.
--
-- Why this exists at all:
--
-- `logs.read` (0007_rbac_seed.sql L90) is declared with scope_kind = 'server'.
-- It answers "may I read logs on this box?", which is the operator's question.
-- It does NOT answer the tenant's question, "may I read the logs of MY site?",
-- and the two are not the same: a customer holding a project-scoped grant
-- cannot satisfy a server-scoped requirement at all, so today the person who
-- owns the site is the one person who cannot read its logs.
--
-- DATABASE.md §6 requires every tenant-bound resource be traceable to its
-- project boundary, and OBSERVABILITY.md L168 requires logs respect tenant
-- boundaries. Those two together mean the permission has to be project-scoped,
-- and the honest way to get there is a new key rather than a change to the
-- meaning of an existing one.
--
-- Why a new key rather than a data migration on `logs.read`:
--
-- Widening `logs.read` from 'server' to 'project' would silently re-scope every
-- existing grant. A binding that was correct under the old meaning — "this
-- operator may read logs on server X" — becomes a different statement under the
-- new one, and the migration that changed it would be indistinguishable from
-- one that widened access by accident. SECURITY.md §5 requires every mutation
-- endpoint to have an explicit permission definition with allow AND deny tests;
-- changing the scope of an existing key quietly satisfies the letter of that
-- rule while defeating its purpose.
--
-- Why the grants are written explicitly:
--
-- The category-based grants in 0007 were evaluated once, when that migration
-- ran. They do not re-evaluate when a new permission is inserted, so a new
-- site-category row would be granted to nobody and the permission would be
-- dead on arrival — which is the same class of defect as a column with a reader
-- and no writer. Every role that can already read a site, or already read logs,
-- is therefore named here.
--
-- The rule is deliberately a UNION rather than an intersection: a role that may
-- read a site, or that may read logs, may read that site's logs. The grant does
-- not widen anyone's reach on its own, because authorization is permission AND
-- scope together — `role_bindings.scope_id` is what confines a grant to one
-- project (0003_rbac.sql L56). Granting the key to a role whose binding is
-- project-scoped yields access to that project's sites and nothing else.

INSERT INTO permissions (key, category, description, scope_kind, requires_step_up) VALUES
  ('site.logs.read', 'site', 'Read the logs of a site within the project', 'project', false);

-- Grant to every role that already holds `site.read` or `logs.read`. Expressed
-- as a query against the existing grants rather than a hand-written role list,
-- so the set is derived from the actual authorization state instead of from a
-- reader's recollection of it.
INSERT INTO role_permissions (role_id, permission_key)
SELECT DISTINCT rp.role_id, 'site.logs.read'
  FROM role_permissions rp
 WHERE rp.permission_key IN ('site.read', 'logs.read');
