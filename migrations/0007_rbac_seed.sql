-- 0007_rbac_seed.sql — canonical permission catalog and built-in roles.
--
-- This is the authoritative list of what JAWAKER can authorize. Every
-- mutation endpoint must reference one of these keys, and adding a key here
-- is a deliberate, reviewed act (SECURITY.md s5: every new mutation endpoint
-- requires an explicit permission definition).
--
-- Deny by default: no role grants a permission that is not listed here.

INSERT INTO permissions (key, category, description, scope_kind, requires_step_up) VALUES
  -- Platform / installation
  ('platform.read',            'platform', 'Read installation-wide platform state',              'global',   false),
  ('platform.manage',          'platform', 'Change installation-wide platform settings',          'global',   true),
  ('settings.read',            'platform', 'Read platform settings',                              'global',   false),
  ('settings.manage',          'platform', 'Change platform settings',                            'global',   true),
  ('updates.read',             'platform', 'View available and applied updates',                  'global',   false),
  ('updates.manage',           'platform', 'Apply panel and module updates',                      'global',   true),

  -- Identity administration
  ('users.read',               'identity', 'List and inspect users',                              'global',   false),
  ('users.manage',             'identity', 'Create, suspend, and modify users',                   'global',   true),
  ('roles.read',               'identity', 'Inspect roles and their permissions',                 'global',   false),
  ('roles.manage',             'identity', 'Create and edit custom roles and bindings',           'global',   true),
  ('sessions.read',            'identity', 'Inspect session and device inventory',                'global',   false),
  ('sessions.revoke',          'identity', 'Revoke sessions (own or others per scope)',           'global',   false),
  ('tokens.manage',            'identity', 'Create and revoke API tokens',                        'global',   false),
  ('impersonation.readonly',   'identity', 'Impersonate another user in read-only mode',          'global',   true),

  -- Servers / nodes
  ('server.read',              'server',   'View server inventory and health',                    'server',   false),
  ('server.manage',            'server',   'Manage a server and its services',                    'server',   false),
  ('server.enroll',            'server',   'Issue node enrollment tokens',                        'global',   true),
  ('server.delete',            'server',   'Remove a server from the fleet',                      'server',   true),

  -- Projects
  ('project.read',             'project',  'View a project',                                      'project',  false),
  ('project.create',           'project',  'Create projects',                                     'global',   false),
  ('project.manage',           'project',  'Change project settings and membership',              'project',  false),
  ('project.delete',           'project',  'Delete a project and its resources',                  'project',  true),

  -- Sites
  ('site.read',                'site',     'View sites and their configuration',                  'project',  false),
  ('site.create',              'site',     'Create sites',                                        'project',  false),
  ('site.manage',              'site',     'Change site configuration (via revision flow)',       'project',  false),
  ('site.delete',              'site',     'Delete a site and its data',                          'project',  true),

  -- Deployments
  ('deployment.read',          'deploy',   'View deployments and history',                        'project',  false),
  ('deployment.create',        'deploy',   'Trigger deployments',                                 'project',  false),
  ('deployment.rollback',      'deploy',   'Roll back to a previous release',                     'project',  false),

  -- Databases
  ('database.read',            'database', 'View managed databases',                              'project',  false),
  ('database.manage',          'database', 'Create/alter managed databases and users',            'project',  false),
  ('database.delete',          'database', 'Delete a managed database',                           'project',  true),

  -- DNS / TLS
  ('dns.read',                 'dns',      'View DNS zones and records',                          'project',  false),
  ('dns.manage',               'dns',      'Change DNS records (via revision flow)',              'project',  false),
  ('ssl.read',                 'tls',      'View certificate inventory',                          'project',  false),
  ('ssl.manage',               'tls',      'Issue, renew, import, and replace certificates',      'project',  false),

  -- Mail (module, arrives later)
  ('mail.read',                'mail',     'View mail domains and mailboxes',                     'project',  false),
  ('mail.manage',              'mail',     'Manage mail configuration',                           'project',  false),

  -- Backups
  ('backup.read',              'backup',   'View backup plans, runs, and recovery catalog',       'project',  false),
  ('backup.create',            'backup',   'Create backup plans and trigger runs',                'project',  false),
  ('backup.restore',           'backup',   'Restore from a backup',                               'project',  true),
  ('backup.delete',            'backup',   'Delete backup artifacts',                             'project',  true),

  -- Secrets
  ('secrets.use',              'secret',   'Reference a secret in configuration',                 'project',  false),
  ('secrets.rotate',           'secret',   'Rotate secret material',                              'project',  true),

  -- Networking / firewall
  ('network.read',             'network',  'View IP, port, and routing inventory',                'server',   false),
  ('network.manage',           'network',  'Change routing and proxy configuration',              'server',   true),
  ('firewall.read',            'network',  'View firewall state and rules',                       'server',   false),
  ('firewall.manage',          'network',  'Apply firewall candidates (Safe Network Apply)',      'server',   true),

  -- Containers
  ('container.read',           'container','View containers, images, volumes, networks',          'project',  false),
  ('container.manage',         'container','Manage container stacks',                             'project',  false),

  -- Operations
  ('jobs.read',                'ops',      'View jobs, steps, and history',                       'global',   false),
  ('jobs.cancel',              'ops',      'Cancel a queued or running job',                      'global',   false),
  ('logs.read',                'ops',      'Read operational and service logs',                   'server',   false),
  ('monitoring.read',          'ops',      'View metrics, alerts, and incidents',                 'server',   false),
  ('audit.read',               'ops',      'Read the audit trail',                                'global',   false),
  ('reports.manage',           'ops',      'Configure scheduled reports and notification routes', 'global',   false),

  -- Modules
  ('modules.read',             'module',   'View module inventory, health, and permissions',      'global',   false),
  ('modules.install',          'module',   'Install and update modules',                          'global',   true),

  -- Security center
  ('security.read',            'security', 'View security findings and events',                   'server',   false),
  ('security.manage',          'security', 'Apply hardening and abuse controls',                  'server',   true),

  -- Interactive terminal (separate from internal privileged operations)
  ('terminal.project',         'terminal', 'Open a project-scoped shell',                         'project',  true),
  ('terminal.root',            'terminal', 'Open an unrestricted root shell',                     'server',   true);

-- Built-in roles. is_builtin = true makes the permission set non-editable and
-- the row non-deletable through the API.
INSERT INTO roles (key, name, description, is_builtin, account_type) VALUES
  ('platform_owner', 'Platform Owner', 'Full authority over the installation.',                       true, 'platform_owner'),
  ('server_admin',   'Server Admin',   'Administrates servers and their services, not billing.',      true, 'server_admin'),
  ('reseller',       'Reseller',       'Manages own customers, projects, and quotas.',                true, 'reseller'),
  ('customer',       'Customer',       'Manages own projects and their resources.',                   true, 'customer'),
  ('project_owner',  'Project Owner',  'Full authority within one project.',                          true, 'customer'),
  ('developer',      'Developer',      'Deploys and manages project workloads; no destructive ops.',  true, 'customer'),
  ('db_manager',     'Database Manager', 'Manages databases within a project.',                       true, 'customer'),
  ('operator',       'Operator',       'Monitors and operates; cannot change configuration.',         true, 'customer'),
  ('viewer',         'Read Only',      'Read-only visibility within scope.',                          true, 'customer');

-- Platform Owner: every permission, global scope. Expressed as an explicit
-- grant of the full catalog rather than a magic superuser flag, so "what can
-- the owner do?" remains answerable by querying the tables.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p WHERE r.key = 'platform_owner';

-- Server Admin: servers, networking, firewall, modules, ops, security.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'server_admin'
      AND p.category IN ('server', 'network', 'module', 'security', 'ops', 'container');

-- Reseller: project/site/db/dns/tls/backup management plus reading users it owns.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'reseller'
      AND p.category IN ('project', 'site', 'database', 'dns', 'tls', 'backup', 'secret');

-- Customer: same operational categories, scoped to their own projects.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'customer'
      AND p.category IN ('project', 'site', 'database', 'dns', 'tls', 'backup', 'secret', 'deploy');

-- Project Owner: everything inside a project.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'project_owner'
      AND p.category IN ('project', 'site', 'database', 'dns', 'tls', 'backup', 'secret', 'deploy', 'container');

-- Developer: deploy + read, no destructive operations.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'developer'
      AND p.key IN ('project.read', 'site.read', 'deployment.read', 'deployment.create',
                    'deployment.rollback', 'database.read', 'logs.read', 'monitoring.read',
                    'jobs.read', 'jobs.cancel', 'secrets.use', 'backup.read', 'backup.create',
                    'container.read', 'container.manage', 'terminal.project');

-- Database Manager: databases plus the reads needed to operate them.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'db_manager'
      AND p.key IN ('database.read', 'database.manage', 'backup.read', 'backup.create',
                    'logs.read', 'monitoring.read', 'secrets.use', 'project.read');

-- Operator: monitor, logs, cancel jobs; no configuration changes.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'operator'
      AND p.key IN ('server.read', 'monitoring.read', 'logs.read', 'jobs.read', 'jobs.cancel',
                    'site.read', 'database.read', 'backup.read', 'container.read',
                    'network.read', 'firewall.read', 'security.read', 'dns.read',
                    'ssl.read', 'deployment.read', 'project.read');

-- Read Only viewer: strictly *.read permissions.
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
    WHERE r.key = 'viewer'
      AND p.key LIKE '%.read';
