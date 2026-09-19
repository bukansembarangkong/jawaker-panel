-- 0006_notifications.sql — notification platform (Phase 1 abstraction).
--
-- The controller routes notification EVENTS to pluggable channels (in-panel
-- now; email/Telegram/webhook arrive with their phases). Delivery is durable
-- and retryable so a channel outage never blocks operations
-- (ARCHITECTURE.md s13).

CREATE TABLE notification_channels (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- in_panel | email | telegram | webhook | discord | slack
    type              text NOT NULL
                      CHECK (type IN ('in_panel', 'email', 'telegram', 'webhook', 'discord', 'slack')),
    name              text NOT NULL,
    -- Routing configuration. Credentials live in the secret subsystem; this
    -- column stores references (secret://...) only.
    config            jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Per-user channel routing with severity filters.
CREATE TABLE notification_routes (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    channel_id        uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    -- Minimum severity to route through this channel: info | warning | critical
    min_severity      text NOT NULL DEFAULT 'info'
                      CHECK (min_severity IN ('info', 'warning', 'critical')),
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX notification_routes_unique_idx
    ON notification_routes (user_id, channel_id);

-- Durable delivery queue. One row per (event, recipient channel) pair so
-- retry state is per-delivery, not per-event.
CREATE TABLE notification_deliveries (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Event key, e.g. "backup.failed", "server.offline" (API.md s15).
    event             text NOT NULL,
    severity          text NOT NULL DEFAULT 'info'
                      CHECK (severity IN ('info', 'warning', 'critical')),
    channel_id        uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    recipient_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    payload           jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Deduplication (DESIGN_SYSTEM.md s19): same unresolved condition is not
    -- re-notified within the dedup window.
    dedup_key         text,
    -- pending | sending | delivered | failed | suppressed | dead_letter
    state             text NOT NULL DEFAULT 'pending'
                      CHECK (state IN ('pending', 'sending', 'delivered', 'failed', 'suppressed', 'dead_letter')),
    attempt_count     integer NOT NULL DEFAULT 0,
    max_attempts      integer NOT NULL DEFAULT 5,
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    last_error        text,
    -- Correlation to the operation that produced the event.
    job_id            uuid,
    request_id        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    delivered_at      timestamptz,
    -- Bounded retention: delivered/failed rows are pruned by a cleanup job.
    expires_at        timestamptz
);

CREATE INDEX notification_deliveries_claim_idx
    ON notification_deliveries (next_attempt_at)
    WHERE state IN ('pending', 'sending');

CREATE INDEX notification_deliveries_dedup_idx
    ON notification_deliveries (dedup_key, created_at DESC)
    WHERE dedup_key IS NOT NULL;

CREATE INDEX notification_deliveries_inbox_idx
    ON notification_deliveries (recipient_id, created_at DESC)
    WHERE state = 'delivered';

CREATE INDEX notification_deliveries_expiry_idx
    ON notification_deliveries (expires_at)
    WHERE expires_at IS NOT NULL;

-- In-panel read state, kept separate so delivery rows stay append-friendly.
CREATE TABLE notification_reads (
    delivery_id       uuid PRIMARY KEY REFERENCES notification_deliveries (id) ON DELETE CASCADE,
    read_at           timestamptz NOT NULL DEFAULT now()
);
