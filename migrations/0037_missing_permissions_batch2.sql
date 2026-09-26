-- 0037_missing_permissions_batch2.sql
-- Adds RBAC permissions that are referenced in controller code but were never
-- seeded into the permissions catalog:
--   ops.read / ops.manage  — production hardening, health checks (global)
--   files.read / files.exec — file manager, terminal task runner (server-scoped)
--   deployment.manage      — pause/stop running deployments (project-scoped)
--   copilot.run            — invoke copilot sessions / apply plans (project-scoped)
--   copilot.review         — review and approve/reject copilot action plans (project-scoped)
--
-- Note: copilot.approve was added in 0036 but the controller uses copilot.review.
-- Both are inserted here idempotently (ON CONFLICT DO NOTHING).

INSERT INTO permissions (key, category, description, scope_kind, requires_step_up) VALUES
  -- Production hardening / health
  ('ops.read',              'ops',        'View health checks, upgrade history, and runbooks',     'global',  false),
  ('ops.manage',            'ops',        'Run on-demand health checks and record runbook events', 'global',  true),

  -- File Manager / Terminal
  ('files.read',            'files',      'Browse and download files via the file manager',        'server',  false),
  ('files.exec',            'files',      'Execute bounded tasks via the terminal task runner',    'server',  true),

  -- Deployment management
  ('deployment.manage',     'deploy',     'Pause, cancel, or modify in-flight deployments',        'project', true),

  -- Copilot (controller uses copilot.run and copilot.review)
  ('copilot.run',           'copilot',    'Invoke copilot sessions and apply approved plans',      'project', true),
  ('copilot.review',        'copilot',    'Review and approve or reject copilot action plans',     'project', true)
ON CONFLICT (key) DO NOTHING;

-- Grant all new permissions to platform_owner.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key
FROM roles r
CROSS JOIN permissions p
WHERE r.key = 'platform_owner'
  AND p.key IN (
    'ops.read', 'ops.manage',
    'files.read', 'files.exec',
    'deployment.manage',
    'copilot.run', 'copilot.review'
  )
ON CONFLICT DO NOTHING;
