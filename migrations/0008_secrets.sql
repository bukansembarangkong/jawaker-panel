-- 0008_secrets.sql — secret storage baseline.
--
-- Scope: at-rest encrypted values referenced by `secret://` URIs
-- (SECURITY.md §8). Phase 1 needs this for TOTP shared secrets; later phases
-- (database passwords, upstream credentials, module config) reuse it.
--
-- Design notes:
--   * The PLAINTEXT is never stored. `ciphertext` is an AEAD envelope that
--     includes the nonce and the associated data binding it to the reference,
--     so a ciphertext moved to another row fails to decrypt instead of
--     silently authenticating the wrong thing.
--   * The encryption key lives OUTSIDE the database (environment/config), so a
--     database dump alone does not disclose secrets. Rotating that key is a
--     re-encryption job; `key_version` records which key sealed each row so the
--     rotation can be done incrementally rather than as one risky migration.
--   * `secret_ref` is the primary key: references are stable and readable, and
--     a duplicate reference is a bug rather than a second secret.
--   * Deletion is a real delete for secret VALUES. Unlike audit rows, a secret
--     value has no historical value once its owners are gone, and keeping
--     retired ciphertext only enlarges the blast radius of a key compromise.
--     The AUDIT trail records that a secret existed and when it changed.

CREATE TABLE secret_values (
    secret_ref    text PRIMARY KEY,
    ciphertext    bytea NOT NULL,
    -- Identifies which master key sealed this row, so key rotation can proceed
    -- row by row instead of all at once.
    key_version   integer NOT NULL DEFAULT 1
                  CHECK (key_version > 0),
    -- Advisory description for operators ("TOTP for owner@example.com"). Never
    -- contains the secret itself.
    description   text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    rotated_at    timestamptz,
    -- Populated when the value is read, so an unused secret can be identified
    -- before it is pruned. Coarse on purpose: this is diagnostics, not audit.
    last_read_at  timestamptz
);

CREATE INDEX secret_values_rotation_idx ON secret_values (key_version, created_at);
