-- Phase 10 — Networking and traffic control
-- Tracks firewall rules, port forwards, network zones, and WireGuard peers
-- per server. All changes go through a candidate/apply workflow matching the
-- site config pattern (Safe Network Apply gate).

-- ── Network zones ─────────────────────────────────────────────────────────────
-- A zone is a named trust boundary (e.g. public, private, management).
-- Rules reference zones rather than raw interface names so a rename does not
-- require rewriting every rule.
CREATE TABLE network_zones (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID NOT NULL REFERENCES servers (id),
    name        TEXT NOT NULL,
    -- e.g. public, private, management, dmz
    kind        TEXT NOT NULL DEFAULT 'custom'
                    CHECK (kind IN ('public','private','management','dmz','custom')),
    -- comma-separated interfaces belonging to this zone
    interfaces  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    CONSTRAINT network_zones_name_len CHECK (length(trim(name)) BETWEEN 1 AND 100)
);

CREATE UNIQUE INDEX network_zones_server_name_idx ON network_zones (server_id, name)
    WHERE deleted_at IS NULL;

-- ── Firewall rules ─────────────────────────────────────────────────────────────
-- Each row is one iptables/nftables rule in a named chain. Rules are ordered
-- by priority within a chain; lower = earlier match.
CREATE TABLE firewall_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers (id),
    -- chain name: INPUT, OUTPUT, FORWARD, or a custom chain
    chain           TEXT NOT NULL,
    priority        INT  NOT NULL DEFAULT 100,
    -- protocol: tcp, udp, icmp, any
    protocol        TEXT NOT NULL DEFAULT 'any'
                        CHECK (protocol IN ('tcp','udp','icmp','any')),
    -- CIDR or empty for any
    source_cidr     TEXT NOT NULL DEFAULT '',
    dest_cidr       TEXT NOT NULL DEFAULT '',
    -- 0 = any
    dest_port_min   INT  NOT NULL DEFAULT 0 CHECK (dest_port_min BETWEEN 0 AND 65535),
    dest_port_max   INT  NOT NULL DEFAULT 0 CHECK (dest_port_max BETWEEN 0 AND 65535),
    -- action: accept, drop, reject, log
    action          TEXT NOT NULL DEFAULT 'accept'
                        CHECK (action IN ('accept','drop','reject','log')),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- free-text description for audit readability
    description     TEXT NOT NULL DEFAULT '',
    -- state: active (applied), candidate (pending apply), archived
    state           TEXT NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active','candidate','archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT firewall_rules_port_range CHECK (dest_port_max = 0 OR dest_port_max >= dest_port_min),
    CONSTRAINT firewall_rules_chain_len  CHECK (length(trim(chain)) BETWEEN 1 AND 64),
    CONSTRAINT firewall_rules_desc_len   CHECK (length(description) <= 500)
);

CREATE INDEX firewall_rules_server_idx ON firewall_rules (server_id, chain, priority)
    WHERE deleted_at IS NULL;
CREATE INDEX firewall_rules_candidate_idx ON firewall_rules (server_id)
    WHERE state = 'candidate' AND deleted_at IS NULL;

-- ── Port forwards ──────────────────────────────────────────────────────────────
-- DNAT/SNAT rules for TCP/UDP traffic. The agent translates these into
-- iptables PREROUTING rules; the controller records them for inventory and
-- conflict detection.
CREATE TABLE port_forwards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers (id),
    protocol        TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    -- host-side binding
    listen_address  TEXT NOT NULL DEFAULT '0.0.0.0',
    listen_port     INT  NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    -- destination
    dest_address    TEXT NOT NULL,
    dest_port       INT  NOT NULL CHECK (dest_port BETWEEN 1 AND 65535),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    description     TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active','candidate','archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT port_forwards_desc_len  CHECK (length(description) <= 500),
    CONSTRAINT port_forwards_addr_len  CHECK (length(trim(listen_address)) BETWEEN 1 AND 45),
    CONSTRAINT port_forwards_daddr_len CHECK (length(trim(dest_address))   BETWEEN 1 AND 45)
);

-- Conflict detection: no two active forwards may bind the same protocol+port.
CREATE UNIQUE INDEX port_forwards_listen_idx ON port_forwards (server_id, protocol, listen_port)
    WHERE state = 'active' AND deleted_at IS NULL;
CREATE INDEX port_forwards_candidate_idx ON port_forwards (server_id)
    WHERE state = 'candidate' AND deleted_at IS NULL;

-- ── WireGuard peers ────────────────────────────────────────────────────────────
-- Records WireGuard peers for the management overlay network. The private key
-- is never stored; only the public key is recorded for peer configuration.
CREATE TABLE wireguard_peers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers (id),
    -- peer's WireGuard public key (base64, 44 chars)
    public_key      TEXT NOT NULL,
    -- human-readable label (e.g. "controller", "node-02")
    label           TEXT NOT NULL DEFAULT '',
    -- allowed IPs for this peer (comma-separated CIDRs)
    allowed_ips     TEXT NOT NULL DEFAULT '',
    -- endpoint address:port (may be empty for dynamic peers)
    endpoint        TEXT NOT NULL DEFAULT '',
    -- keepalive interval in seconds (0 = disabled)
    persistent_keepalive INT NOT NULL DEFAULT 0
                             CHECK (persistent_keepalive BETWEEN 0 AND 65535),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT wireguard_peers_pubkey_len CHECK (length(trim(public_key)) BETWEEN 40 AND 48),
    CONSTRAINT wireguard_peers_label_len  CHECK (length(label) <= 200)
);

CREATE UNIQUE INDEX wireguard_peers_pubkey_idx ON wireguard_peers (server_id, public_key)
    WHERE deleted_at IS NULL;
CREATE INDEX wireguard_peers_server_idx ON wireguard_peers (server_id)
    WHERE deleted_at IS NULL;

-- ── Network apply log ─────────────────────────────────────────────────────────
-- Records the outcome of each Safe Network Apply attempt. On rollback the
-- previous_state_json captures what was restored, enabling recovery audits.
CREATE TABLE network_apply_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id           UUID NOT NULL REFERENCES servers (id),
    -- applied_by: user ID or 'system'
    applied_by          TEXT NOT NULL,
    -- outcome: applied, rolled_back, failed
    outcome             TEXT NOT NULL
                            CHECK (outcome IN ('applied','rolled_back','failed')),
    -- summary of changes (counts by type)
    changes_json        JSONB NOT NULL DEFAULT '{}',
    -- snapshot of the previous state for rollback reference
    previous_state_json JSONB NOT NULL DEFAULT '{}',
    error_message       TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX network_apply_log_server_idx ON network_apply_log (server_id, created_at DESC);
