-- 0033_attack_mode.sql — Emergency DDoS Under Attack Mode (PRD §21.4).

CREATE TABLE server_attack_mode (
    server_id         uuid PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    enabled           boolean NOT NULL DEFAULT false,
    rate_limit_multiplier numeric NOT NULL DEFAULT 5.0, -- Multiplier to tighten rate limits
    challenge_suspicious  boolean NOT NULL DEFAULT true,
    restrict_expensive    boolean NOT NULL DEFAULT true,
    activated_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    activated_at      timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now()
);
