-- Phase 16: Plugin SDK and third-party ecosystem
-- plugins: installed plugin registry with signing/trust levels
-- plugin_permissions: declared permissions per plugin
-- plugin_installs: install/update/uninstall lifecycle events
-- plugin_quarantines: quarantine records for broken/untrusted plugins

BEGIN;

-- plugins: master registry of installed plugins
CREATE TABLE plugins (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL,
    author       TEXT NOT NULL DEFAULT '',
    homepage_url TEXT NOT NULL DEFAULT '',
    manifest     JSONB NOT NULL DEFAULT '{}',
    trust_level  TEXT NOT NULL DEFAULT 'unverified'
                 CHECK (trust_level IN ('unverified', 'community', 'verified', 'official')),
    state        TEXT NOT NULL DEFAULT 'installed'
                 CHECK (state IN ('installing', 'installed', 'enabled', 'disabled', 'quarantined', 'removed')),
    signature    TEXT NOT NULL DEFAULT '',  -- detached signature of manifest
    checksum     TEXT NOT NULL DEFAULT '',  -- sha256 of plugin archive
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- plugin_permissions: permissions each plugin requests
-- (no plugin gets implicit privilege — must be explicitly declared and reviewed)
CREATE TABLE plugin_permissions (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    plugin_id   TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL,
    scope_kind  TEXT NOT NULL DEFAULT 'project'
                CHECK (scope_kind IN ('global', 'project', 'server')),
    granted     BOOLEAN NOT NULL DEFAULT false,
    granted_by  TEXT,
    granted_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plugin_id, permission)
);

-- plugin_installs: lifecycle history (install/update/uninstall)
CREATE TABLE plugin_installs (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    plugin_id    TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL
                 CHECK (event_type IN ('install', 'update', 'enable', 'disable', 'uninstall', 'quarantine', 'restore')),
    from_version TEXT NOT NULL DEFAULT '',
    to_version   TEXT NOT NULL DEFAULT '',
    initiated_by TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- plugin_quarantines: quarantine records for broken/untrusted plugins
CREATE TABLE plugin_quarantines (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    plugin_id    TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL,
    quarantined_by TEXT NOT NULL,
    resolved     BOOLEAN NOT NULL DEFAULT false,
    resolved_by  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ
);

CREATE INDEX idx_plugins_trust_level ON plugins(trust_level);
CREATE INDEX idx_plugins_state       ON plugins(state);
CREATE INDEX idx_plugin_perms_plugin ON plugin_permissions(plugin_id);
CREATE INDEX idx_plugin_installs_plugin ON plugin_installs(plugin_id);
CREATE INDEX idx_plugin_installs_at    ON plugin_installs(occurred_at DESC);
CREATE INDEX idx_plugin_quarantines_plugin ON plugin_quarantines(plugin_id);

COMMIT;
