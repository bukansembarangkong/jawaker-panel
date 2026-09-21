-- 0016_apps_deployments.sql — Phase 4 application deployment data model:
-- applications, environment variables/secrets references, durable deployments,
-- atomic releases, and git webhook tokens.
--
-- Scope: PRD.md §10 (Application Deployment Modes), §11 (Full Deployment Control Plane),
-- §20.4 (Secrets), §24.4 (Secrets in Git: references only), §37 (Core Data Model:
-- Runtime, Deployment, Environment, Secret Reference), IMPLEMENTATION_PLAN.md Phase 4.

-- Applications: managed workloads (Node.js, Bun, Python, etc.) running on a node.
-- One app belongs to one project and runs on one server (same single-server scoping
-- decision as sites, docs/decisions.md D-003).
CREATE TABLE apps (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    server_id           uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    slug                text NOT NULL,
    name                text NOT NULL,
    -- node | bun | python | php | static (PRD.md §10, IMPLEMENTATION_PLAN.md Phase 4)
    runtime_type        text NOT NULL
                        CHECK (runtime_type IN ('node', 'bun', 'python', 'php', 'static')),
    -- active | suspended | pending_delete | deleted (DATABASE.md §7)
    state               text NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active', 'suspended', 'pending_delete', 'deleted')),

    -- Git repository source.
    git_repo_url        text NOT NULL DEFAULT '',
    git_ref_default     text NOT NULL DEFAULT 'main',
    -- Secret reference to git credentials (SSH deploy key or access token).
    -- Must be an opaque secret:// URI; raw credentials are NEVER stored here
    -- (PRD.md §20.4, DATABASE.md §12).
    git_credential_ref  text,

    -- Build and start command specification.
    -- Program must come from the runtime allowlist (validated in Go).
    -- Arguments are stored as a JSON array of strings (argv slice, no shell).
    build_program       text NOT NULL DEFAULT '',
    build_args          jsonb NOT NULL DEFAULT '[]'::jsonb,
    start_program       text NOT NULL DEFAULT '',
    start_args          jsonb NOT NULL DEFAULT '[]'::jsonb,
    working_dir         text NOT NULL DEFAULT '',

    -- Port the managed application listens on. Static apps may have NULL port.
    port                integer CHECK (port IS NULL OR (port BETWEEN 1024 AND 65535)),
    -- Optional HTTP health probe path (e.g. /healthz or /api/health).
    health_path         text,
    -- Environment label (default 'production').
    env_name            text NOT NULL DEFAULT 'production',

    created_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    delete_after        timestamptz,
    deleted_at          timestamptz,

    CONSTRAINT apps_slug_present  CHECK (btrim(slug) <> ''),
    CONSTRAINT apps_name_present  CHECK (btrim(name) <> ''),
    CONSTRAINT apps_slug_safe     CHECK (slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    CONSTRAINT apps_slug_length   CHECK (char_length(slug) BETWEEN 3 AND 48),
    CONSTRAINT apps_deleted_shape CHECK (
        (state = 'deleted') = (deleted_at IS NOT NULL)
    ),
    CONSTRAINT apps_delete_after_shape CHECK (
        (state = 'pending_delete') = (delete_after IS NOT NULL)
    ),
    CONSTRAINT apps_git_cred_ref_format CHECK (
        git_credential_ref IS NULL OR git_credential_ref ~ '^secret://'
    )
);

-- Slug is unique per project among non-deleted apps.
CREATE UNIQUE INDEX apps_slug_unique_idx ON apps (project_id, slug) WHERE deleted_at IS NULL;
CREATE INDEX apps_project_state_idx ON apps (project_id, state);
CREATE INDEX apps_server_idx ON apps (server_id) WHERE deleted_at IS NULL;

-- Environment variables and secret references per application.
-- Plaintext secret values are NEVER stored in this table.
-- Sensitive values point to secret_values via secret_ref (PRD.md §20.4, DATABASE.md §12).
CREATE TABLE app_env_vars (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id        uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    name          text NOT NULL,
    value_source  text NOT NULL CHECK (value_source IN ('literal', 'secret_ref')),
    literal_value text,
    secret_ref    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT app_env_vars_name_safe CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]*$'),
    CONSTRAINT app_env_vars_source_shape CHECK (
        (value_source = 'literal' AND literal_value IS NOT NULL AND secret_ref IS NULL) OR
        (value_source = 'secret_ref' AND secret_ref IS NOT NULL AND literal_value IS NULL)
    ),
    CONSTRAINT app_env_vars_secret_ref_format CHECK (
        secret_ref IS NULL OR secret_ref ~ '^secret://'
    )
);

CREATE UNIQUE INDEX app_env_vars_name_unique_idx ON app_env_vars (app_id, name);

-- Deployments: records of deployment attempts and state progression.
-- Tied to a durable background job (PRD.md §27.1).
CREATE TABLE app_deployments (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id           uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    project_id       uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    server_id        uuid NOT NULL REFERENCES servers (id) ON DELETE RESTRICT,
    trigger          text NOT NULL CHECK (trigger IN ('manual', 'webhook', 'rollback')),
    commit_sha       text,
    git_ref          text NOT NULL DEFAULT 'main',
    state            text NOT NULL DEFAULT 'queued'
                     CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'rolled_back', 'canceled')),
    error_code       text NOT NULL DEFAULT '',
    error_summary    text NOT NULL DEFAULT '',
    job_id           uuid REFERENCES jobs (id) ON DELETE SET NULL,
    requested_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    idempotency_key  text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz,

    CONSTRAINT app_deployments_commit_sha_format CHECK (
        commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{7,40}$'
    )
);

CREATE INDEX app_deployments_app_created_idx ON app_deployments (app_id, created_at DESC);
CREATE INDEX app_deployments_job_idx ON app_deployments (job_id) WHERE job_id IS NOT NULL;
CREATE UNIQUE INDEX app_deployments_idempotency_idx ON app_deployments (app_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- First line of defence against concurrent deployments on the same app.
-- Only one deployment may be queued or running at a time per application.
CREATE UNIQUE INDEX app_deployments_single_active_idx ON app_deployments (app_id)
    WHERE state IN ('queued', 'running');

-- Releases: atomic deployment targets with symlink tracking (PRD.md §11.3).
CREATE TABLE app_releases (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id         uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    deployment_id  uuid NOT NULL REFERENCES app_deployments (id) ON DELETE RESTRICT,
    release_path   text NOT NULL,
    commit_sha     text NOT NULL DEFAULT '',
    is_current     bool NOT NULL DEFAULT false,
    health_state   text NOT NULL DEFAULT 'unknown'
                   CHECK (health_state IN ('unknown', 'healthy', 'unhealthy')),
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT app_releases_path_present CHECK (btrim(release_path) <> '')
);

CREATE INDEX app_releases_app_created_idx ON app_releases (app_id, created_at DESC);
-- Exactly one release may be marked current per application.
CREATE UNIQUE INDEX app_releases_single_current_idx ON app_releases (app_id)
    WHERE is_current = true;

-- Webhook tokens for git provider push triggers.
-- Plaintext token is only displayed once upon creation.
-- Table stores only SHA-256 hash (PRD.md §11, §26.4, SECURITY.md).
CREATE TABLE app_webhook_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    token_hash  text NOT NULL,
    state       text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,

    CONSTRAINT app_webhook_tokens_hash_present CHECK (btrim(token_hash) <> '')
);

CREATE UNIQUE INDEX app_webhook_tokens_hash_unique_idx ON app_webhook_tokens (token_hash);
CREATE INDEX app_webhook_tokens_app_idx ON app_webhook_tokens (app_id);
