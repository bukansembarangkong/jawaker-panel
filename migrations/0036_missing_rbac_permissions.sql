-- 0036_missing_rbac_permissions.sql
-- Adds RBAC permissions for HA, Copilot, and Plugins modules that were
-- implemented in later phases but never seeded into the permissions catalog.
-- platform_owner role inherits them automatically via the CROSS JOIN grants.

INSERT INTO permissions (key, category, description, scope_kind, requires_step_up) VALUES
  -- High Availability
  ('ha.read',              'ha',       'View HA pools, members, events, and drills',        'project', false),
  ('ha.manage',            'ha',       'Create and modify HA pools and membership',          'project', false),
  ('ha.delete',            'ha',       'Delete HA pools',                                   'project', true),

  -- AI Copilot
  ('copilot.read',         'copilot',  'View copilot sessions, plans, and approvals',        'project', false),
  ('copilot.manage',       'copilot',  'Create copilot sessions and submit plans',           'project', false),
  ('copilot.approve',      'copilot',  'Review and approve/reject copilot action plans',     'project', true),

  -- Plugins
  ('plugins.read',         'plugins',  'View installed plugins and their permissions',       'global',  false),
  ('plugins.manage',       'plugins',  'Install, enable, disable, and uninstall plugins',   'global',  true),
  ('plugins.review',       'plugins',  'Grant permissions and quarantine/restore plugins',  'global',  true)
ON CONFLICT (key) DO NOTHING;

-- platform_owner already has a CROSS JOIN grant that ran at seed time.
-- We need to explicitly add the new permissions to platform_owner now.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key
FROM roles r
CROSS JOIN permissions p
WHERE r.key = 'platform_owner'
  AND p.key IN (
    'ha.read', 'ha.manage', 'ha.delete',
    'copilot.read', 'copilot.manage', 'copilot.approve',
    'plugins.read', 'plugins.manage', 'plugins.review'
  )
ON CONFLICT DO NOTHING;
