-- Phase 9 — Container Platform
-- Tracks Docker/OCI host inventory, containers, images, volumes, networks,
-- Compose stacks, and private registries at the project level.

-- ── Container registries ──────────────────────────────────────────────────────
CREATE TABLE container_registries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects (id),
    name            TEXT NOT NULL,
    -- e.g. docker.io, ghcr.io, registry.example.com
    host            TEXT NOT NULL,
    -- sealed via secret.Store; never stored plaintext
    secret_ref      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT container_registries_name_len  CHECK (length(trim(name))  BETWEEN 1 AND 200),
    CONSTRAINT container_registries_host_len  CHECK (length(trim(host))  BETWEEN 1 AND 500),
    CONSTRAINT container_registries_no_slash  CHECK (host NOT LIKE '%/%')
);

CREATE INDEX container_registries_project_idx ON container_registries (project_id) WHERE deleted_at IS NULL;

-- ── Docker/OCI images ─────────────────────────────────────────────────────────
CREATE TABLE container_images (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects (id),
    server_id       UUID REFERENCES servers (id),
    registry_id     UUID REFERENCES container_registries (id),
    -- e.g. nginx:1.25-alpine
    reference       TEXT NOT NULL,
    image_id        TEXT,          -- sha256:... from Docker
    size_bytes      BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT container_images_reference_len CHECK (length(trim(reference)) BETWEEN 1 AND 500)
);

CREATE INDEX container_images_project_idx ON container_images (project_id) WHERE deleted_at IS NULL;

-- ── Compose stacks ────────────────────────────────────────────────────────────
CREATE TABLE compose_stacks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects (id),
    server_id       UUID NOT NULL REFERENCES servers (id),
    name            TEXT NOT NULL,
    -- e.g. active, stopped, degraded, updating
    state           TEXT NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active','stopped','degraded','updating','removed')),
    -- current compose YAML stored as text for diff/audit
    compose_yaml    TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT compose_stacks_name_len CHECK (length(trim(name)) BETWEEN 1 AND 200)
);

CREATE UNIQUE INDEX compose_stacks_unique_idx ON compose_stacks (server_id, name)
    WHERE deleted_at IS NULL;

-- ── Containers ────────────────────────────────────────────────────────────────
CREATE TABLE containers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects (id),
    server_id       UUID NOT NULL REFERENCES servers (id),
    stack_id        UUID REFERENCES compose_stacks (id),
    -- Docker container name (or ID fallback)
    name            TEXT NOT NULL,
    container_id    TEXT,          -- Docker container ID (short or full)
    image_ref       TEXT NOT NULL, -- image reference used at start
    -- running, stopped, paused, restarting, exited, dead
    state           TEXT NOT NULL DEFAULT 'running'
                        CHECK (state IN ('running','stopped','paused','restarting','exited','dead','unknown')),
    -- resource limits (0 = unlimited)
    cpu_limit       REAL NOT NULL DEFAULT 0,
    mem_limit_mb    INT  NOT NULL DEFAULT 0,
    -- Gate: unsafe privileged containers flagged
    privileged      BOOLEAN NOT NULL DEFAULT false,
    -- health check state: healthy, unhealthy, starting, none
    health          TEXT NOT NULL DEFAULT 'none'
                        CHECK (health IN ('healthy','unhealthy','starting','none')),
    started_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX containers_project_idx ON containers (project_id) WHERE deleted_at IS NULL;
CREATE INDEX containers_server_idx  ON containers (server_id)  WHERE deleted_at IS NULL;
CREATE INDEX containers_stack_idx   ON containers (stack_id)   WHERE stack_id IS NOT NULL AND deleted_at IS NULL;

-- Partial index for running-container queries.
CREATE INDEX containers_running_idx ON containers (server_id, state) WHERE state = 'running' AND deleted_at IS NULL;

-- ── Container volumes ─────────────────────────────────────────────────────────
CREATE TABLE container_volumes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects (id),
    server_id       UUID NOT NULL REFERENCES servers (id),
    container_id    UUID REFERENCES containers (id),
    -- Docker volume name
    name            TEXT NOT NULL,
    driver          TEXT NOT NULL DEFAULT 'local',
    mount_point     TEXT,
    size_bytes      BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT container_volumes_name_len CHECK (length(trim(name)) BETWEEN 1 AND 300)
);

CREATE INDEX container_volumes_project_idx ON container_volumes (project_id) WHERE deleted_at IS NULL;
CREATE INDEX container_volumes_server_idx  ON container_volumes (server_id)  WHERE deleted_at IS NULL;
