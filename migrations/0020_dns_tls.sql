-- 0020_dns_tls.sql — Phase 8 DNS and TLS control plane.
--
-- Delivers:
--   dns_providers    — Cloudflare (and future provider) credentials, project-scoped.
--   dns_zones        — hosted zone registry, one provider per zone.
--   dns_records      — desired-state record inventory with drift detection fields.
--   cert_orders      — ACME order state machine (DNS-01, wildcard ready).
--
-- The existing `certificates` table (migrations/0014) already owns the inventory.
-- This migration adds the DNS layer and the ACME order lifecycle only.
--
-- Security notes:
--   - dns_providers.credentials is a secret:// reference into secret_values.
--     The raw API token NEVER appears in this table (SECURITY.md §8).
--   - No private key material lives here; see certificates.secret_ref.

-- ── DNS providers ───────────────────────────────────────────────────────────
CREATE TABLE dns_providers (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name         text NOT NULL,
    -- 'cloudflare' is the only implemented adapter; others stubbed.
    provider     text NOT NULL CHECK (provider IN ('cloudflare', 'route53', 'manual')),
    -- secret:// reference — never the raw token.
    secret_ref   text NOT NULL,
    enabled      boolean NOT NULL DEFAULT true,
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT dns_providers_name_present CHECK (btrim(name) <> '')
);

CREATE INDEX dns_providers_project_idx ON dns_providers (project_id);

-- ── DNS zones ────────────────────────────────────────────────────────────────
CREATE TABLE dns_zones (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    provider_id     uuid NOT NULL REFERENCES dns_providers (id) ON DELETE RESTRICT,
    -- FQDN without trailing dot, e.g. "example.com"
    apex            text NOT NULL,
    -- Provider-side zone ID (e.g. Cloudflare zone_id).
    external_id     text,
    -- 'active' | 'degraded' | 'paused'
    state           text NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'degraded', 'paused')),
    -- When the provider was last successfully reached for this zone.
    last_synced_at  timestamptz,
    -- Human-readable last error from the provider (cleared on success).
    last_error      text,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT dns_zones_apex_present CHECK (btrim(apex) <> ''),
    -- One registration per apex per project.
    CONSTRAINT dns_zones_apex_project_unique UNIQUE (project_id, apex)
);

CREATE INDEX dns_zones_provider_idx ON dns_zones (provider_id);

-- ── DNS records ──────────────────────────────────────────────────────────────
-- Desired state. Drift is detected when `external_id` is set but the provider
-- returns a different `value` or `ttl` than stored here.
CREATE TABLE dns_records (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id      uuid NOT NULL REFERENCES dns_zones (id) ON DELETE CASCADE,
    -- Record type: A, AAAA, CNAME, MX, TXT, SRV, CAA, NS.
    rtype        text NOT NULL
                 CHECK (rtype IN ('A','AAAA','CNAME','MX','TXT','SRV','CAA','NS')),
    -- Relative name within the zone, '@' for apex.
    name         text NOT NULL,
    value        text NOT NULL,
    ttl          int  NOT NULL DEFAULT 300 CHECK (ttl BETWEEN 60 AND 86400),
    priority     int,           -- MX / SRV priority
    -- Provider-side record ID; NULL means not yet pushed.
    external_id  text,
    -- 'pending' | 'synced' | 'drifted' | 'deleting'
    sync_state   text NOT NULL DEFAULT 'pending'
                 CHECK (sync_state IN ('pending','synced','drifted','deleting')),
    managed      boolean NOT NULL DEFAULT true, -- false = imported / read-only
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT dns_records_name_present  CHECK (btrim(name) <> ''),
    CONSTRAINT dns_records_value_present CHECK (btrim(value) <> '')
);

CREATE INDEX dns_records_zone_idx      ON dns_records (zone_id);
CREATE INDEX dns_records_sync_idx      ON dns_records (sync_state) WHERE sync_state IN ('pending','drifted');

-- ── ACME / TLS orders ────────────────────────────────────────────────────────
-- State machine for DNS-01 challenge issuance.
-- Actual ACME HTTP calls are performed by the node agent after the controller
-- publishes 'acme.challenge.needed' (YAGNI: no direct ACME lib in controller).
CREATE TABLE cert_orders (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The certificate this order will produce (pre-allocated so we can link).
    certificate_id uuid REFERENCES certificates (id) ON DELETE SET NULL,
    project_id     uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    provider_id    uuid REFERENCES dns_providers (id) ON DELETE SET NULL,
    -- Identifiers requested (may include wildcards: *.example.com).
    identifiers    text[] NOT NULL,
    -- ACME directory URL, e.g. Let's Encrypt production.
    directory_url  text NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory',
    -- 'pending' | 'ready' | 'processing' | 'valid' | 'invalid' | 'canceled'
    state          text NOT NULL DEFAULT 'pending'
                   CHECK (state IN ('pending','ready','processing','valid','invalid','canceled')),
    -- Provider-side ACME order URL once created.
    order_url      text,
    -- DNS-01 challenge token and key auth (set when challenge is placed).
    challenge_token    text,
    challenge_key_auth text,
    -- DNS record placed for challenge (cleared after validation).
    challenge_record_id uuid REFERENCES dns_records (id) ON DELETE SET NULL,
    -- When the DNS record was placed (TTL guard).
    challenge_placed_at timestamptz,
    -- Error message on invalid state.
    error_message  text,
    expires_at     timestamptz,
    completed_at   timestamptz,
    created_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cert_orders_identifiers_nonempty CHECK (cardinality(identifiers) > 0),
    CONSTRAINT cert_orders_completed_shape CHECK (
        (state IN ('valid','invalid','canceled')) = (completed_at IS NOT NULL)
    )
);

CREATE INDEX cert_orders_project_idx  ON cert_orders (project_id, created_at DESC);
CREATE INDEX cert_orders_pending_idx  ON cert_orders (state, created_at)
    WHERE state IN ('pending','ready','processing');

-- RBAC seeds for new permissions.
-- platform_owner gets ALL (0007 line 123–124 selects all permissions).
-- reseller / customer / project_owner category grants include 'dns' and 'tls'
-- (0007 lines 132–148), so inserting the rows here is enough — those grants
-- run once at migration time via the CROSS JOIN, but the rows inserted here
-- will be picked up only by future grant-management operations. Because 0007
-- is already applied, explicitly grant to the existing roles below.
INSERT INTO permissions (key, category, description, scope_kind, requires_step_up) VALUES
    ('dns.read',   'dns', 'View DNS zones, records, and providers',                      'project', false),
    ('dns.write',  'dns', 'Create, update, and delete DNS zones, records, and providers','project', false),
    ('tls.read',   'tls', 'View certificates and ACME orders',                           'project', false),
    ('tls.write',  'tls', 'Import, renew, revoke, and bind certificates',                'project', false)
ON CONFLICT (key) DO NOTHING;

-- Grant to every role whose category coverage includes dns/tls.
-- platform_owner: all. reseller/customer/project_owner: dns+tls category.
-- operator/viewer: dns.read + tls.read only (mirrors existing ssl.read/dns.read grants).
INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key
  FROM roles r CROSS JOIN permissions p
 WHERE r.key = 'platform_owner'
   AND p.key IN ('dns.read','dns.write','tls.read','tls.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key
  FROM roles r CROSS JOIN permissions p
 WHERE r.key IN ('reseller','customer','project_owner')
   AND p.key IN ('dns.read','dns.write','tls.read','tls.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_key)
SELECT r.id, p.key
  FROM roles r CROSS JOIN permissions p
 WHERE r.key IN ('operator','viewer','developer')
   AND p.key IN ('dns.read','tls.read')
ON CONFLICT DO NOTHING;


