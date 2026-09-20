-- 0012_node_enrollment.sql — node inventory, enrollment tokens, node identity.
--
-- Scope: the control-plane half of node enrollment (SECURITY.md §6, PRD.md §6.2,
-- ARCHITECTURE.md §3.4). What this schema must make TRUE rather than merely
-- possible:
--
--   * an enrollment token is single-use because ONE conditional UPDATE can
--     claim it, so two concurrent redemptions cannot both succeed. Single-use
--     is a database property here, not application logic that a future caller
--     could bypass;
--   * an enrollment token is CONTROLLER-BOUND: the row names the controller
--     identity it was minted for, so a token exfiltrated from one installation
--     is useless against another;
--   * the plaintext token is never stored. Only its SHA-256 digest is, so no
--     read of this table — including a database dump — yields a usable token;
--   * a server is never hard-deleted. It transitions to 'deleted' and its
--     certificate history survives, because audit and revision rows reference
--     it and must stay resolvable (DATABASE.md §7).
--
-- Design notes:
--   * `controller_identity` is a singleton enforced by a unique constraint on
--     a constant column, not by application convention. Its id is what node
--     certificates are bound to, so it must be created once and never reused.
--   * `node_certificates` records every issued serial so revocation is a local
--     question ("is this serial revoked?") rather than a CRL file that has to
--     be distributed to every node before it takes effect.
--   * `node_identities` carries the full SPIFFE URI, which is the identity the
--     node actually authenticates with. Duplicating it here means an operator
--     can see who a server IS without decoding a certificate.

-- The installation's own identity. Exactly one row.
--
-- The singleton constraint uses a constant column rather than a CHECK on a
-- counter: a UNIQUE index on a column that can only hold one value makes a
-- second INSERT fail inside the database, where no code path can forget to
-- check.
CREATE TABLE controller_identity (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Stable name for operators and for the pin a node stores.
    name        text NOT NULL,
    singleton   boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT controller_identity_singleton_key UNIQUE (singleton),
    CONSTRAINT controller_identity_name_present CHECK (btrim(name) <> '')
);

-- A managed server. In standalone mode the controller's own host is also a
-- server row, so there is one model to reason about rather than two.
CREATE TABLE servers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL,
    description   text NOT NULL DEFAULT '',
    -- host:port the controller dials to reach the agent's mTLS listener.
    -- Empty while the server is still pending enrollment.
    address       text NOT NULL DEFAULT '',
    -- pending | active | suspended | deleted  (DATABASE.md §7)
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'active', 'suspended', 'deleted')),
    -- Coarse rollup of the newest certificate's state, so a list view does not
    -- have to join and compare timestamps per row.
    cert_status   text NOT NULL DEFAULT 'none'
                  CHECK (cert_status IN ('none', 'active', 'expiring', 'expired', 'revoked')),
    os_family     text NOT NULL DEFAULT '',
    os_version    text NOT NULL DEFAULT '',
    agent_version text NOT NULL DEFAULT '',
    -- Release level of the newest heartbeat, and the newest capabilities scan.
    last_seen_at  timestamptz,
    enrolled_at   timestamptz,
    capabilities_observed_at timestamptz,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    deleted_at    timestamptz,

    CONSTRAINT servers_deleted_shape CHECK (
        (status = 'deleted') = (deleted_at IS NOT NULL)
    )
);

-- Name uniqueness applies only to servers that are still in service. A deleted
-- server keeps its name for audit readability without blocking an operator
-- from reusing it.
CREATE UNIQUE INDEX servers_name_unique_idx ON servers (name) WHERE deleted_at IS NULL;

-- The list view is ordered by newest enrollment and filtered by status.
CREATE INDEX servers_status_created_idx ON servers (status, created_at DESC);

-- One-time enrollment tokens (SECURITY.md §6, PRD.md §6.2).
--
-- `token_hash` is the PRIMARY KEY of the useful sense: a duplicate digest would
-- mean two rows describing one token, and the conditional UPDATE that claims a
-- token must have exactly one row to claim.
CREATE TABLE enrollment_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 digest of the presented token. The plaintext exists only in the
    -- HTTP response that created it.
    token_hash    bytea NOT NULL UNIQUE,
    -- Controller binding: a token minted by installation A cannot enroll a node
    -- into installation B.
    controller_id uuid NOT NULL REFERENCES controller_identity (id) ON DELETE RESTRICT,
    -- Intended node name, so an operator can tell which token is which without
    -- having enrolled anything yet.
    node_name     text NOT NULL,
    expires_at    timestamptz NOT NULL,
    -- Set by the single atomic claim. Its NULL-ness IS the unused state.
    used_at       timestamptz,
    used_by_server_id uuid REFERENCES servers (id) ON DELETE SET NULL,
    revoked_at    timestamptz,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT enrollment_tokens_node_name_present CHECK (btrim(node_name) <> ''),
    CONSTRAINT enrollment_tokens_expiry_after_creation CHECK (expires_at > created_at),
    -- A token that was used cannot also have been revoked: the states are
    -- mutually exclusive, and allowing both would make "why was this refused?"
    -- unanswerable.
    CONSTRAINT enrollment_tokens_terminal_exclusive CHECK (
        used_at IS NULL OR revoked_at IS NULL
    )
);

-- Partial index for the hot path: "is there a live token with this digest?".
-- Dead tokens are excluded so the index stays small no matter how many are
-- minted over the installation's life.
CREATE INDEX enrollment_tokens_live_idx
    ON enrollment_tokens (expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;

-- The long-lived identity a node acquires at enrollment. One per server: a node
-- has one identity, and re-enrollment rotates it rather than adding a second.
CREATE TABLE node_identities (
    server_id     uuid PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    controller_id uuid NOT NULL REFERENCES controller_identity (id) ON DELETE RESTRICT,
    -- Full SPIFFE URI, e.g. spiffe://jawaker/node/<uuid>. This is the value the
    -- node authenticates with, and it is stored so an operator can read the
    -- identity without decoding a certificate.
    node_uri      text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    rotated_at    timestamptz,

    CONSTRAINT node_identities_uri_present CHECK (btrim(node_uri) <> '')
);

-- Every certificate ever issued to a node, so revocation is answerable locally.
--
-- The controller never needs to publish a CRL to the fleet: it holds the
-- authoritative list and checks the presented serial on each connection. A
-- revoked certificate therefore stops working at the next connection instead of
-- at the next CRL distribution.
CREATE TABLE node_certificates (
    -- Lowercase hex of the certificate serial number. Text rather than numeric
    -- because the value is an opaque identifier that is compared for equality,
    -- never ordered or arithmetically used.
    serial        text PRIMARY KEY,
    server_id     uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    -- SHA-256 of the DER, for operators matching a certificate on the host to
    -- the row here.
    fingerprint   text NOT NULL,
    not_before    timestamptz NOT NULL,
    not_after     timestamptz NOT NULL,
    issued_at     timestamptz NOT NULL DEFAULT now(),
    superseded_at timestamptz,
    revoked_at    timestamptz,
    revoke_reason text,

    CONSTRAINT node_certificates_serial_present CHECK (btrim(serial) <> ''),
    CONSTRAINT node_certificates_window CHECK (not_after > not_before),
    -- A revocation without a reason is an audit gap: "who revoked this and
    -- why?" would be unanswerable. A revoked_at with an empty reason is refused
    -- by the database rather than by reviewer discipline.
    CONSTRAINT node_certificates_revoke_reason CHECK (
        revoked_at IS NULL OR btrim(coalesce(revoke_reason, '')) <> ''
    )
);

-- Validity sweep: "which certificates are expiring soon?" and the per-server
-- lookup used when validating a connection.
CREATE INDEX node_certificates_server_idx ON node_certificates (server_id, not_after DESC);
CREATE INDEX node_certificates_revoked_idx ON node_certificates (revoked_at) WHERE revoked_at IS NOT NULL;
