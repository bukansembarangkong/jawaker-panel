-- 0017_databases.sql — Phase 5 managed databases data model:
-- databases, database users/privileges, and local database backup records.
--
-- Scope: PRD.md §12 (Core Data Platform), §12.1 (Engines: PostgreSQL, MariaDB/MySQL),
-- §12.4 (Features: DB/user ownership, granular privileges, encrypted credentials,
-- credential rotation, backup verification), §20.4 (Secrets),
-- §37 (Core Data Model: Database, Database User, Secret Reference),
-- IMPLEMENTATION_PLAN.md Phase 5.

-- Managed databases: local database instances running on a node.
-- One database belongs to one project and runs on one server.
CREATE TABLE managed_databases (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    server_id           uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    slug                text NOT NULL,
    name                text NOT NULL,
    -- postgresql | mariadb (PRD.md §12.1, IMPLEMENTATION_PLAN.md Phase 5)
    engine              text NOT NULL
                        CHECK (engine IN ('postgresql', 'mariadb')),
    engine_version      text NOT NULL DEFAULT '',
    -- The actual database name on the engine (e.g. jw_proj_mydb)
    db_name             text NOT NULL,
    -- active | suspended | pending_delete | deleted (DATABASE.md §7)
    state               text NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active', 'suspended', 'pending_delete', 'deleted')),

    created_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    delete_after        timestamptz,
    deleted_at          timestamptz,

    CONSTRAINT databases_slug_present  CHECK (btrim(slug) <> ''),
    CONSTRAINT databases_name_present  CHECK (btrim(name) <> ''),
    CONSTRAINT databases_slug_safe     CHECK (slug ~ '^[a-z0-9]([a-z0-9_]*[a-z0-9])?$'),
    CONSTRAINT databases_slug_length   CHECK (char_length(slug) BETWEEN 2 AND 48),
    CONSTRAINT databases_db_name_safe  CHECK (db_name ~ '^[a-z0-9_]{2,63}$'),
    CONSTRAINT databases_deleted_shape CHECK (
        (state = 'deleted') = (deleted_at IS NOT NULL)
    ),
    CONSTRAINT databases_delete_after_shape CHECK (
        (state = 'pending_delete') = (delete_after IS NOT NULL)
    )
);

-- Slug is unique per project among non-deleted databases.
CREATE UNIQUE INDEX databases_project_slug_idx ON managed_databases (project_id, slug)
    WHERE deleted_at IS NULL;
-- The engine-level db_name must be globally unique per server among non-deleted databases.
CREATE UNIQUE INDEX databases_server_dbname_idx ON managed_databases (server_id, db_name)
    WHERE deleted_at IS NULL;
CREATE INDEX databases_project_state_idx ON managed_databases (project_id, state);
CREATE INDEX databases_server_idx ON managed_databases (server_id) WHERE deleted_at IS NULL;

-- Database users and their scoped privileges.
-- Passwords are NEVER stored here; secret_ref points to secret_values (PRD.md §20.4, DATABASE.md §12).
CREATE TABLE database_users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id         uuid NOT NULL REFERENCES managed_databases (id) ON DELETE CASCADE,
    username            text NOT NULL,
    secret_ref          text NOT NULL,
    -- Privileges granted to this user (JSON array of strings, e.g. ["SELECT","INSERT","UPDATE","DELETE"])
    privileges          jsonb NOT NULL DEFAULT '["ALL"]'::jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz,

    CONSTRAINT database_users_username_safe CHECK (username ~ '^[a-z0-9_]{2,32}$'),
    CONSTRAINT database_users_secret_ref_format CHECK (secret_ref ~ '^secret://')
);

-- Username is unique per database among active (non-revoked) users.
CREATE UNIQUE INDEX database_users_db_user_idx ON database_users (database_id, username)
    WHERE revoked_at IS NULL;
CREATE INDEX database_users_db_idx ON database_users (database_id);

-- Database backup records: local dump artifacts for point-in-time recovery testing.
-- Tied to a durable background job (PRD.md §27.1).
CREATE TABLE database_backups (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id         uuid NOT NULL REFERENCES managed_databases (id) ON DELETE CASCADE,
    project_id          uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    server_id           uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    trigger             text NOT NULL CHECK (trigger IN ('manual', 'scheduled', 'pre_upgrade', 'pre_delete')),
    state               text NOT NULL DEFAULT 'queued'
                        CHECK (state IN ('queued', 'running', 'completed', 'failed')),
    dump_path           text NOT NULL DEFAULT '',
    size_bytes          bigint NOT NULL DEFAULT 0,
    sha256              text NOT NULL DEFAULT '',
    job_id              uuid REFERENCES jobs (id) ON DELETE SET NULL,
    requested_by        uuid REFERENCES users (id) ON DELETE SET NULL,
    idempotency_key     text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    started_at          timestamptz,
    completed_at        timestamptz,

    CONSTRAINT database_backups_size_positive CHECK (size_bytes >= 0)
);

CREATE INDEX database_backups_db_created_idx ON database_backups (database_id, created_at DESC);
CREATE INDEX database_backups_job_idx ON database_backups (job_id) WHERE job_id IS NOT NULL;
CREATE UNIQUE INDEX database_backups_idempotency_idx ON database_backups (database_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
