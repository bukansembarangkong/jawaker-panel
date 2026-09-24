-- 0034_app_previews.sql
-- PRD §11.6 Preview Deployments: Ephemeral branch/PR environments with automated teardown

CREATE TABLE IF NOT EXISTS app_previews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    pr_number INTEGER,
    preview_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deploying', 'terminated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_app_previews_app_id ON app_previews(app_id, status);
CREATE INDEX IF NOT EXISTS idx_app_previews_project_id ON app_previews(project_id);
