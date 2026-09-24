-- Phase 15: AI Infrastructure Copilot
-- copilot_sessions: tracks each copilot analysis/plan conversation
-- copilot_tool_calls: immutable audit of every tool call made by AI
-- copilot_approvals: approval requests for risky mutations
-- copilot_plans: generated change plans awaiting review/approval

BEGIN;

-- copilot_sessions: one per AI interaction thread
CREATE TABLE copilot_sessions (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    project_id   TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'active'
                 CHECK (state IN ('active', 'completed', 'cancelled')),
    intent       TEXT NOT NULL DEFAULT '',  -- user's stated intent
    context      JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- copilot_tool_calls: immutable audit log of every AI tool invocation
-- (no DELETE, no UPDATE — append-only for compliance)
CREATE TABLE copilot_tool_calls (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    session_id   TEXT NOT NULL REFERENCES copilot_sessions(id) ON DELETE RESTRICT,
    tool_name    TEXT NOT NULL,
    tool_input   JSONB NOT NULL DEFAULT '{}',
    tool_output  JSONB NOT NULL DEFAULT '{}',
    outcome      TEXT NOT NULL DEFAULT 'ok'
                 CHECK (outcome IN ('ok', 'error', 'denied', 'pending_approval')),
    error_msg    TEXT NOT NULL DEFAULT '',
    called_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- copilot_plans: AI-generated change plans
CREATE TABLE copilot_plans (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    session_id   TEXT NOT NULL REFERENCES copilot_sessions(id) ON DELETE CASCADE,
    project_id   TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    steps        JSONB NOT NULL DEFAULT '[]',
    risk_level   TEXT NOT NULL DEFAULT 'low'
                 CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    state        TEXT NOT NULL DEFAULT 'draft'
                 CHECK (state IN ('draft', 'pending_approval', 'approved', 'rejected', 'applied', 'cancelled')),
    created_by   TEXT NOT NULL,
    reviewed_by  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- copilot_approvals: approval requests for high-risk plans
CREATE TABLE copilot_approvals (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    plan_id      TEXT NOT NULL REFERENCES copilot_plans(id) ON DELETE CASCADE,
    requested_by TEXT NOT NULL,
    reviewed_by  TEXT,
    state        TEXT NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending', 'approved', 'rejected', 'expired')),
    comment      TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_copilot_sessions_project ON copilot_sessions(project_id);
CREATE INDEX idx_copilot_sessions_user    ON copilot_sessions(user_id);
CREATE INDEX idx_copilot_tool_calls_session ON copilot_tool_calls(session_id);
CREATE INDEX idx_copilot_tool_calls_called  ON copilot_tool_calls(called_at DESC);
CREATE INDEX idx_copilot_plans_session    ON copilot_plans(session_id);
CREATE INDEX idx_copilot_plans_project    ON copilot_plans(project_id);
CREATE INDEX idx_copilot_approvals_plan   ON copilot_approvals(plan_id);

COMMIT;
