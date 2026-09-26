-- 0038_site_nodejs_runtime.sql — add 'nodejs' site mode and per-site Node.js
-- runtime configuration table.
--
-- Scope: Node.js per-site runtime management (PR-1).
--
-- The `mode` column in `sites` was created with an INLINE unnamed CHECK (no CONSTRAINT
-- name, so it cannot be dropped by name). PostgreSQL gives inline checks a
-- system-generated name of the form sites_mode_check. We drop it by that name
-- and re-add it to include 'nodejs'.
--
-- `sites_upstream_matches_mode` is a NAMED constraint (0014 L213); we drop and
-- re-add it to cover nodejs as well, since a nodejs site also stores its port as
-- the upstream address.

-- Extend the mode allowlist.
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_mode_check;
ALTER TABLE sites ADD CONSTRAINT sites_mode_check
    CHECK (mode IN ('static', 'php', 'reverse_proxy', 'nodejs'));

-- nodejs sites carry their port in upstream (e.g. "127.0.0.1:3000"), so they
-- need a non-empty upstream just like reverse_proxy sites.
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_upstream_matches_mode;
ALTER TABLE sites ADD CONSTRAINT sites_upstream_matches_mode
    CHECK ((mode IN ('reverse_proxy', 'nodejs')) = (btrim(upstream) <> ''));

-- Per-site Node.js runtime configuration.
-- One row per site (UNIQUE site_id). Created lazily when the operator first
-- configures Node.js for a site; absent rows mean "use platform defaults".
CREATE TABLE site_nodejs_configs (
    id           text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    site_id      uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    -- 'system' means whichever node is on PATH; a numeric string like '20'
    -- or '22' is resolved via nvm/n; a full path is used verbatim.
    node_version text NOT NULL DEFAULT 'system',
    -- Relative to doc_root. Empty string means doc_root itself.
    app_root     text NOT NULL DEFAULT '',
    startup_file text NOT NULL DEFAULT 'server.js',
    -- CLI arguments passed to node after the startup file.
    start_args   jsonb NOT NULL DEFAULT '[]',
    -- Environment variables injected into the process environment.
    env_vars     jsonb NOT NULL DEFAULT '{}',
    -- The port the Node.js process listens on (written to nginx upstream).
    port         integer NOT NULL DEFAULT 3000
                 CHECK (port BETWEEN 1024 AND 65535),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (site_id)
);

CREATE INDEX site_nodejs_configs_site_id_idx ON site_nodejs_configs (site_id);
