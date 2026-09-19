-- 0003_rbac.sql — role-based access control with resource scopes.
--
-- Model (PRD s5.2, SECURITY.md s5):
--   role -> permissions, and bindings are resource-scoped so a Reseller can
--   hold "site.create" on their own project but not on someone else's.
--
-- Permissions are referenced by their canonical string (e.g. "site.create")
-- rather than a numeric id so audit rows and API responses stay readable and
-- stable across environments.
--
-- Deny by default: a permission is granted only by an unexpired binding whose
-- resource scope matches. There is no implicit superuser flag on users; the
-- platform owner holds explicit wildcard bindings instead.

CREATE TABLE permissions (
    -- Canonical permission key; the primary key IS the identifier.
    key               text PRIMARY KEY,
    category          text NOT NULL,
    description       text NOT NULL,
    -- Permissions that can be scoped to a specific resource instance vs those
    -- that are inherently global (e.g. "updates.manage").
    scope_kind        text NOT NULL DEFAULT 'global'
                      CHECK (scope_kind IN ('global', 'server', 'project', 'resource')),
    -- High-risk permissions may additionally require step-up authentication
    -- or an approval workflow (PRD s28.3).
    requires_step_up  boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Machine key for built-in roles; NULL for custom roles.
    key               text UNIQUE,
    name              text NOT NULL,
    description       text NOT NULL DEFAULT '',
    -- Built-in roles cannot be deleted or have their permission set edited.
    is_builtin        boolean NOT NULL DEFAULT false,
    -- Account class this role is intended for; advisory, not enforced.
    account_type      text
                      CHECK (account_type IS NULL OR account_type IN
                             ('platform_owner', 'server_admin', 'reseller', 'customer')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role_id           uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_key    text NOT NULL REFERENCES permissions (key) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_key)
);

-- A binding grants a role to a principal within an explicit resource scope.
--
--   scope_type = 'global'  -> scope_id must be NULL (whole installation)
--   scope_type = 'server'  -> scope_id is a servers.id
--   scope_type = 'project' -> scope_id is a projects.id
--   scope_type = 'resource'-> scope_id is a resource id the module defines
--
-- The CHECK constraint keeps malformed scopes out of the database, so
-- authorization queries never have to guess what an empty scope means.
CREATE TABLE role_bindings (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id           uuid NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    scope_type        text NOT NULL
                      CHECK (scope_type IN ('global', 'server', 'project', 'resource')),
    scope_id          uuid,
    -- Temporary access with expiry (PRD s5.2).
    expires_at        timestamptz,
    -- Optional IP restriction for privileged bindings.
    allowed_cidrs     inet[],
    -- Impersonation and automation attribution.
    granted_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at        timestamptz,

    CONSTRAINT role_bindings_scope_shape CHECK (
        (scope_type = 'global' AND scope_id IS NULL)
        OR (scope_type <> 'global' AND scope_id IS NOT NULL)
    )
);

-- Authorization lookup path: "which bindings does this user have, for which
-- scope, still valid?" Partial index keeps the hot query narrow.
CREATE INDEX role_bindings_user_active_idx
    ON role_bindings (user_id, scope_type, scope_id)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX role_bindings_unique_idx
    ON role_bindings (user_id, role_id, scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE revoked_at IS NULL;
