-- Migration 0035: AI Copilot LLM Provider Configuration (PRD §28).
-- Stores endpoint, provider type, model, and optional encrypted API key.
CREATE TABLE IF NOT EXISTS copilot_provider_configs (
    id            TEXT PRIMARY KEY DEFAULT 'default',
    provider_type TEXT NOT NULL DEFAULT 'openai_compatible',
    endpoint      TEXT NOT NULL DEFAULT 'https://api.openai.com/v1',
    api_key       TEXT NOT NULL DEFAULT '',
    model         TEXT NOT NULL DEFAULT 'gpt-4o',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
