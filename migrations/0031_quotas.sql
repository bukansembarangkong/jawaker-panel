-- 0031_quotas.sql — project resource limits and quotas (PRD §5.5).
CREATE TABLE project_quotas (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    resource      text NOT NULL
                  CHECK (resource IN ('sites', 'databases', 'apps', 'memory_mb', 'storage_gb', 'bandwidth_gb', 'backups')),
    limit_value   bigint NOT NULL DEFAULT -1, -- -1 = unlimited
    current_value bigint NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, resource)
);

CREATE INDEX idx_project_quotas_project ON project_quotas (project_id);
