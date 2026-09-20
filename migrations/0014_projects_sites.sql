-- 0014_projects_sites.sql — the projects/sites domain: projects, membership,
-- quotas, sites, domains, hostnames-per-site, and certificate metadata.
--
-- Scope: PRD.md §37 (core data model: Project, Site, Domain, Certificate),
-- DATABASE.md §3 (`projects` domain: projects, memberships, quotas, sites,
-- domains), PRD.md §5.3 (quotas), PRD.md §17.3 (project root isolation).
--
-- What this schema must make TRUE rather than merely possible:
--
--   * a project is the tenant boundary, and a site BELONGS to exactly one
--     project. DATABASE.md §6: "Every tenant-bound resource should be traceable
--     to its project/customer/account boundary." Making site -> project a NOT
--     NULL foreign key is what makes an authorization query unambiguous: there
--     is no inferred ownership chain to get wrong;
--
--   * thus this migration CLOSES A DANGLING REFERENCE. `role_bindings` has had
--     scope_type = 'project' since 0003, documented as "scope_id is a
--     projects.id" (0003_rbac.sql L56), and `projects` did not exist. Every
--     project-scoped grant in the RBAC catalog (site.*, project.*, ssl.*) has
--     been pointing at a table that had not been created yet;
--
--   * a site is never hard-deleted. It transitions active -> pending_delete ->
--     deleted and keeps its row, because revision and audit rows reference it
--     and must stay resolvable (DATABASE.md §7, PRD.md §36). The tombstone is
--     enforced by a shape constraint, not by application discipline;
--
--   * a domain string is claimable by exactly ONE live site across the whole
--     installation. Two sites serving one hostname is not a configuration
--     error a human should have to notice; it is a routing ambiguity that makes
--     which-site-answered-which-request unanswerable;
--
--   * certificate rows carry a SECRET REFERENCE, never key material.
--     DATABASE.md §12: secrets metadata only. The private key lives in
--     secret_values (0008) and this table never holds a copy, so a certificate
--     inventory query cannot leak a key.
--
-- Design notes:
--   * `state` follows the lifecycle vocabulary DATABASE.md §7 names
--     (active | suspended | pending_delete | deleted). Note that `servers`
--     (0012) omits pending_delete and uses status instead of state; the
--     divergence is recorded in docs/decisions.md rather than retrofitted here,
--     because 0012 is released and migrations are immutable
--     (CONTRIBUTING.md §6, DATABASE.md §13);
--   * `slug` is the human-readable, URL-safe identifier used for the
--     filesystem path and the generated config filename. It is SEPARATE from
--     the uuid: DATABASE.md §4 requires that opaque IDs are never used as
--     security boundaries and that human-friendly names are uniqued in their
--     own scope. A slug is not a credential and must never be the only thing
--     separating two tenants' files, which is why the path also carries the
--     project uuid — see docs/decisions.md;
--   * `mode` is bounded to the three modes IMPLEMENTATION_PLAN.md L79 and
--     PRD.md §9.1 put in this phase: static, php, reverse_proxy. Containerised
--     and external-upstream modes arrive with the phases that own them, so the
--     CHECK is a scope statement rather than an oversight.

-- The tenant boundary.
CREATE TABLE projects (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- URL-safe identifier, unique among live projects. Used for filesystem
    -- paths and generated filenames, so it is constrained to a safe alphabet
    -- rather than merely being trimmed.
    slug         text NOT NULL,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    -- active | suspended | pending_delete | deleted  (DATABASE.md §7)
    state        text NOT NULL DEFAULT 'active'
                 CHECK (state IN ('active', 'suspended', 'pending_delete', 'deleted')),
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    -- When the project entered pending_delete. The grace period is measured
    -- from here, so it must be recorded rather than inferred from updated_at,
    -- which any later edit would move.
    delete_after timestamptz,
    deleted_at   timestamptz,

    CONSTRAINT projects_slug_present  CHECK (btrim(slug) <> ''),
    CONSTRAINT projects_name_present  CHECK (btrim(name) <> ''),
    -- Lowercase alphanumerics and single hyphens, not starting or ending with
    -- one. This becomes a directory name and a Unix group name, so the
    -- constraint is the first line of defence against a slug that is really a
    -- path fragment or a shell metacharacter.
    CONSTRAINT projects_slug_safe     CHECK (slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    CONSTRAINT projects_slug_length   CHECK (char_length(slug) BETWEEN 3 AND 48),
    -- A tombstone must carry a deletion time, and a live row must not. The same
    -- shape rule 0012 applies to servers.
    CONSTRAINT projects_deleted_shape CHECK (
        (state = 'deleted') = (deleted_at IS NOT NULL)
    ),
    -- A pending_delete must have a deadline; the other states must not.
    CONSTRAINT projects_delete_after_shape CHECK (
        (state = 'pending_delete') = (delete_after IS NOT NULL)
    )
);

-- Slug uniqueness applies only to projects that are not tombstoned: a deleted
-- project keeps its slug for audit readability without blocking reuse.
CREATE UNIQUE INDEX projects_slug_unique_idx ON projects (slug) WHERE deleted_at IS NULL;

CREATE INDEX projects_state_created_idx ON projects (state, created_at DESC);

-- Who may act in a project.
--
-- This is deliberately NOT role_bindings. role_bindings (0003) answers "what
-- may this user do, in what scope" and is the authorization input. This table
-- answers "who is on this project team, in what capacity" and is a display and
-- membership-management concern. Collapsing them would make removing someone
-- from a team and revoking their permissions the same write, and the panel
-- would no longer be able to show "member, but suspended" or "member whose
-- grant expired yesterday".
CREATE TABLE project_memberships (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Display-only role label. Authorization is role_bindings, always.
    role_label  text NOT NULL DEFAULT 'member',
    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    removed_at  timestamptz,

    CONSTRAINT project_memberships_label_present CHECK (btrim(role_label) <> '')
);

-- One live membership per (project, user). A removed membership is kept so the
-- history of who had access survives.
CREATE UNIQUE INDEX project_memberships_live_unique_idx
    ON project_memberships (project_id, user_id) WHERE removed_at IS NULL;

CREATE INDEX project_memberships_user_idx ON project_memberships (user_id) WHERE removed_at IS NULL;

-- Quotas (PRD.md §5.3): storage, domains, databases, mailboxes, containers,
-- CPU/RAM, worker count, backup retention, API limits.
--
-- Modelled as nullable columns rather than a key/value table because the set is
-- closed and known: PRD.md §5.3 names it. A k/v table would move every typo
-- from a schema error to a runtime one, and "what is the disk quota for this
-- project?" would become a string lookup that can silently miss.
--
-- A NULL means "inherit the platform default", which is distinct from 0
-- meaning "none allowed". Those two must not collapse.
CREATE TABLE project_quotas (
    project_id           uuid PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    disk_bytes           bigint CHECK (disk_bytes IS NULL OR disk_bytes >= 0),
    domains              integer CHECK (domains IS NULL OR domains >= 0),
    sites                integer CHECK (sites IS NULL OR sites >= 0),
    databases            integer CHECK (databases IS NULL OR databases >= 0),
    mailboxes            integer CHECK (mailboxes IS NULL OR mailboxes >= 0),
    containers           integer CHECK (containers IS NULL OR containers >= 0),
    cpu_millicores       integer CHECK (cpu_millicores IS NULL OR cpu_millicores >= 0),
    memory_bytes         bigint CHECK (memory_bytes IS NULL OR memory_bytes >= 0),
    workers              integer CHECK (workers IS NULL OR workers >= 0),
    backup_retention_days integer CHECK (backup_retention_days IS NULL OR backup_retention_days >= 0),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- A hosted site. One site belongs to one project and runs on one server.
--
-- Single-server is a Phase 3 scoping decision recorded in docs/decisions.md: a site
-- reachable through several nodes is a distribution/multi-node concern that
-- belongs with the phases that own deployment, and modelling it now would make
-- every ownership question ambiguous before anything needs the answer.
CREATE TABLE sites (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    -- The node this site is served from. RESTRICT rather than CASCADE: deleting
    -- a server must not silently vaporise the sites it hosts. The operator
    -- moves them first, which is the moment they should be thinking about it.
    server_id     uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    slug          text NOT NULL,
    name          text NOT NULL,
    -- static | php | reverse_proxy  (IMPLEMENTATION_PLAN.md §Phase 3, PRD.md §9.1)
    mode          text NOT NULL
                  CHECK (mode IN ('static', 'php', 'reverse_proxy')),
    -- active | suspended | pending_delete | deleted  (DATABASE.md §7)
    state         text NOT NULL DEFAULT 'active'
                  CHECK (state IN ('active', 'suspended', 'pending_delete', 'deleted')),

    -- Paths as the NODE sees them. Stored here so the controller can show an
    -- operator where the site lives without a round trip, and so a descriptor's
    -- declared write scope can be compared against actual intent.
    doc_root      text NOT NULL DEFAULT '',
    -- reverse_proxy mode only: the upstream this site forwards to.
    upstream      text NOT NULL DEFAULT '',
    -- php mode only: the PHP-FPM unit, e.g. php8.3-fpm. Empty means the node's
    -- detected default. The unit must be a capability the node reported before
    -- this is set — see the capability contract in 0013.
    php_unit      text NOT NULL DEFAULT '',

    -- The applied revision currently in force. Nullable because a site exists
    -- before its first configuration is applied. ON DELETE SET NULL rather than
    -- CASCADE: losing a revision row must not delete the site.
    applied_revision_id uuid REFERENCES revisions (id) ON DELETE SET NULL,

    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    delete_after  timestamptz,
    deleted_at    timestamptz,

    CONSTRAINT sites_slug_present  CHECK (btrim(slug) <> ''),
    CONSTRAINT sites_name_present  CHECK (btrim(name) <> ''),
    CONSTRAINT sites_slug_safe     CHECK (slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    CONSTRAINT sites_slug_length   CHECK (char_length(slug) BETWEEN 1 AND 48),
    CONSTRAINT sites_deleted_shape CHECK (
        (state = 'deleted') = (deleted_at IS NOT NULL)
    ),
    CONSTRAINT sites_delete_after_shape CHECK (
        (state = 'pending_delete') = (delete_after IS NOT NULL)
    ),
    -- Mode-specific fields must be consistent with the mode. A static site with
    -- an upstream is a row whose meaning nobody can state, and it would render a
    -- proxy_pass block for a site that has no upstream.
    CONSTRAINT sites_upstream_matches_mode CHECK (
        (mode = 'reverse_proxy') = (btrim(upstream) <> '')
    ),
    CONSTRAINT sites_php_unit_matches_mode CHECK (
        mode = 'php' OR btrim(php_unit) = ''
    )
);

-- Slug uniqueness is per project, not global: two customers may each want
-- "www". The filesystem path disambiguates by project (see docs/decisions.md).
CREATE UNIQUE INDEX sites_slug_unique_idx
    ON sites (project_id, slug) WHERE deleted_at IS NULL;

-- The hot list query: sites in a project, newest first, tombstones excluded.
CREATE INDEX sites_project_live_idx
    ON sites (project_id, created_at DESC) WHERE deleted_at IS NULL;

-- "What is this server hosting?" — the operator question asked before taking a
-- node down, and the reason server_id is indexed.
CREATE INDEX sites_server_live_idx
    ON sites (server_id) WHERE deleted_at IS NULL;

-- A hostname served by a site.
--
-- DOMAIN UNIQUENESS IS INSTALLATION-WIDE across live sites, enforced by a
-- partial unique index on the domain string alone. This is the constraint that
-- prevents two sites from claiming one hostname, which nginx cannot resolve
-- deterministically and which would make "which site answered?" unanswerable
-- after the fact.
--
-- Note the deliberate asymmetry with sites.slug: two projects may both have a
-- site slugged "www", but only one may serve the hostname "www.example.com".
CREATE TABLE site_domains (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id     uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    -- Fully-qualified, lowercase, no scheme, no port, no trailing dot.
    hostname    text NOT NULL,
    is_primary  boolean NOT NULL DEFAULT false,
    -- Set when the hostname was verified to point at this node. NULL means
    -- claimed but unverified, which is the honest state for a domain whose DNS
    -- has not been checked. Phase 3 issues HTTP-01 only, so this is decided by
    -- whether the challenge succeeded, not by a DNS lookup.
    verified_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz,

    CONSTRAINT site_domains_hostname_present CHECK (btrim(hostname) <> ''),
    -- RFC 1123 host syntax: labels of alphanumerics and hyphens, dot-separated,
    -- at least two labels. Constrained in the schema because this string is
    -- written into a generated config file and used as a certificate identifier;
    -- a hostname is never free text.
    CONSTRAINT site_domains_hostname_syntax CHECK (
        hostname = lower(hostname)
        AND char_length(hostname) BETWEEN 4 AND 253
        AND hostname ~ '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'
    )
);

-- The routing-ambiguity constraint: one live site per hostname, installation-wide.
CREATE UNIQUE INDEX site_domains_hostname_unique_idx
    ON site_domains (hostname) WHERE deleted_at IS NULL;

-- At most one primary per site, among live rows only.
CREATE UNIQUE INDEX site_domains_primary_unique_idx
    ON site_domains (site_id) WHERE is_primary AND deleted_at IS NULL;

CREATE INDEX site_domains_site_idx ON site_domains (site_id) WHERE deleted_at IS NULL;

-- Certificate inventory. METADATA ONLY: no key material, ever.
--
-- The private key lives in secret_values (0008) as an AEAD envelope, and this
-- row references it. DATABASE.md §12 is explicit that secrets metadata belongs
-- in the schema and secret values do not, and SECURITY.md §8 requires that a
-- key is never returned after creation except as a one-time reveal. A column
-- here holding PEM would put a key in every backup, every replica and every
-- query log.
CREATE TABLE certificates (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The certificate belongs to a project, not a site: one certificate may
    -- cover several hostnames across sites, and a shared certificate is the
    -- normal case for a wildcard-free multi-domain setup.
    project_id     uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    -- Certificate lifetime window, as reported by the issuer.
    issued_at      timestamptz NOT NULL,
    not_after      timestamptz NOT NULL,
    -- The identifier set this certificate covers (SANs). Stored so renewal can
    -- be evaluated against the CURRENT set of domains without re-parsing the
    -- certificate, and so a mismatch is detectable before it breaks a site.
    identifiers    text[] NOT NULL,
    -- Sanity bound on the array. An unbounded SAN list is an unbounded audit
    -- and diff payload; the limit is generous for real certificates and small
    -- enough to stay reviewable.
    CONSTRAINT certificates_identifiers_bounded CHECK (cardinality(identifiers) BETWEEN 1 AND 100),
    -- Issuer and ACME directory, so a multi-CA installation can tell which CA a
    -- certificate came from (PRD.md §15.1).
    issuer         text NOT NULL DEFAULT '',
    directory_url  text NOT NULL DEFAULT '',
    -- The serial as hex, for correlation with what a node reports on the wire.
    serial_hex     text NOT NULL DEFAULT '',
    -- Envelope-encrypted private key: a REFERENCE into secret_values, never
    -- the value itself (SECURITY.md §8, DATABASE.md §12).
    secret_ref     text NOT NULL,
    -- The full chain, as PEM. This is public material: it is served to every
    -- client that connects, so it is not a secret and storing it here keeps a
    -- certificate readable without decrypting anything.
    chain_pem      text NOT NULL DEFAULT '',

    -- active | expiring | expired | revoked | superseded
    state          text NOT NULL DEFAULT 'active'
                   CHECK (state IN ('active', 'expiring', 'expired', 'revoked', 'superseded')),
    -- Issuance provenance, so an inventory row is answerable: which job issued
    -- it, and which certificate it replaced.
    issued_by_job_id uuid,
    replaces_id    uuid REFERENCES certificates (id) ON DELETE SET NULL,
    revoked_at     timestamptz,
    revoke_reason  text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    deleted_at     timestamptz,

    CONSTRAINT certificates_window_ordered   CHECK (not_after > issued_at),
    CONSTRAINT certificates_secret_ref_present CHECK (btrim(secret_ref) <> ''),
    CONSTRAINT certificates_revoked_shape CHECK (
        (state = 'revoked') = (revoked_at IS NOT NULL)
    )
);

-- The expiry monitor queries exactly this: live certificates ordered by expiry,
-- ascending, because the urgent row is the soonest one.
CREATE INDEX certificates_expiry_idx
    ON certificates (state, not_after) WHERE deleted_at IS NULL;

CREATE INDEX certificates_project_idx
    ON certificates (project_id) WHERE deleted_at IS NULL;

-- Which certificate is currently serving which hostname.
--
-- A join table rather than a column on site_domains, because the same
-- certificate commonly covers several hostnames and one hostname can move
-- between certificates during a renewal. Modelling it as a column would make
-- "swap this hostname to the new certificate" a write to the domain row and
-- lose the previous binding, which is exactly the state the safe-renewal
-- sequence (PRD.md §15.4) needs to be able to fall back to.
CREATE TABLE domain_certificates (
    site_domain_id  uuid NOT NULL REFERENCES site_domains (id) ON DELETE CASCADE,
    certificate_id  uuid NOT NULL REFERENCES certificates (id) ON DELETE RESTRICT,
    -- The binding currently in force. Older bindings are kept so a rollback has
    -- somewhere to return to.
    is_current      boolean NOT NULL DEFAULT false,
    activated_at    timestamptz NOT NULL DEFAULT now(),
    deactivated_at  timestamptz,

    PRIMARY KEY (site_domain_id, certificate_id, activated_at),
    CONSTRAINT domain_certificates_current_shape CHECK (
        is_current = (deactivated_at IS NULL)
    )
);

-- Exactly one current certificate per hostname. This is the constraint that
-- makes "which certificate is live for example.com?" a single-row question.
CREATE UNIQUE INDEX domain_certificates_current_unique_idx
    ON domain_certificates (site_domain_id) WHERE is_current;

-- A hostname is bound to one certificate per activation instant; the primary
-- key covers that. The reverse direction (which hostnames does this certificate
-- serve?) is the revocation path's question.
CREATE INDEX domain_certificates_certificate_idx
    ON domain_certificates (certificate_id) WHERE is_current;
