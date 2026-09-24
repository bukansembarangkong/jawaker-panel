-- 0032_automation_rules_webhooks.sql — Automation Rules and Outbound Webhooks (PRD §26.4, §26.5).

CREATE TABLE automation_rules (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    -- Event trigger key: e.g. "disk.pressure", "deployment.failed", "backup.failed", "server.offline"
    trigger_event  text NOT NULL,
    -- JSON structure representing condition e.g. {"field": "disk_pct", "comparator": "gt", "value": 90}
    condition      jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Action to take: "notify", "incident_open", "job_postpone", "service_restart"
    action_type    text NOT NULL,
    action_target  jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled        boolean NOT NULL DEFAULT true,
    last_triggered_at timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_automation_rules_trigger ON automation_rules (trigger_event) WHERE enabled = true;

CREATE TABLE outbound_webhooks (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    target_url     text NOT NULL,
    secret_token   text NOT NULL, -- Used to compute HMAC-SHA256 signature in X-Jawaker-Signature header
    event_filter   text[] NOT NULL DEFAULT '{}'::text[], -- empty means all events
    enabled        boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbound_webhook_deliveries (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id     uuid NOT NULL REFERENCES outbound_webhooks(id) ON DELETE CASCADE,
    event          text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'delivered', 'failed', 'dead_letter')),
    status_code    integer,
    error_message  text,
    attempt_count  integer NOT NULL DEFAULT 0,
    max_attempts   integer NOT NULL DEFAULT 5,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_deliveries_pending ON outbound_webhook_deliveries (next_attempt_at)
    WHERE status IN ('pending');
CREATE INDEX idx_webhook_deliveries_webhook ON outbound_webhook_deliveries (webhook_id, created_at DESC);
