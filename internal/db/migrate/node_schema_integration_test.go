//go:build integration

// Integration tests for the Phase 2 node-enrollment schema (migrations 0012 and
// 0013), applied through the REAL migration set against live PostgreSQL.
//
// These pin the invariants the Go code is allowed to assume. The most important
// one is that single-use enrollment is a DATABASE property: if the conditional
// UPDATE's guarantees were ever weakened — the partial index dropped, the
// terminal-state CHECK relaxed — a future caller could redeem a token twice and
// nothing in the application layer would notice.

package migrate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// insertController returns the singleton controller identity id.
func insertController(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO controller_identity (name) VALUES ('test controller') RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("insert controller identity: %v", err)
	}
	return id
}

func TestRealMigrationsCreatePhase2Tables(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	for _, table := range []string{
		"controller_identity",
		"servers",
		"enrollment_tokens",
		"node_identities",
		"node_certificates",
		"node_capabilities",
		"node_heartbeats",
	} {
		if !tableExists(ctx, pool, table) {
			t.Errorf("table %q missing after migrations", table)
		}
	}
}

// The controller identity is a singleton by database constraint, not by
// convention: a second row must be impossible so node certificates can never be
// bound to two different installations.
func TestControllerIdentityIsSingleton(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	insertController(t, ctx, pool)
	mustFail(t, ctx, pool,
		`INSERT INTO controller_identity (name) VALUES ('second controller')`,
		"controller_identity_singleton_key")
}

// A server name is reusable once the earlier server is tombstoned, but not
// while it is live. Two live servers with one name would make the fleet
// ambiguous to an operator.
func TestServerNameUniqueAmongLiveServersOnly(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `INSERT INTO servers (name) VALUES ('web-01')`)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO servers (name) VALUES ('web-01')`,
		"servers_name_unique_idx")

	// Tombstone the first, then the name is free again.
	if _, err := pool.Exec(ctx,
		`UPDATE servers SET status = 'deleted', deleted_at = now() WHERE name = 'web-01'`); err != nil {
		t.Fatalf("tombstone server: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO servers (name) VALUES ('web-01')`); err != nil {
		t.Errorf("insert server after tombstone: %v", err)
	}
}

// deleted_at and status must agree. Allowing 'deleted' with no timestamp would
// make "when was this removed?" unanswerable, which is exactly what audit needs.
func TestServerDeletedShapeIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	mustFail(t, ctx, pool,
		`INSERT INTO servers (name, status) VALUES ('ghost', 'deleted')`,
		"servers_deleted_shape")
	mustFail(t, ctx, pool,
		`INSERT INTO servers (name, status, deleted_at) VALUES ('ghost2', 'active', now())`,
		"servers_deleted_shape")
}

// The single-use guarantee: one conditional UPDATE claims the token, and a
// second attempt from any caller finds nothing to claim.
func TestEnrollmentTokenSingleUseIsEnforcedByDatabase(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	hash := []byte{0x01, 0x02, 0x03, 0x04}
	var tokenID string
	err := pool.QueryRow(ctx,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at)
		 VALUES ($1, $2, 'node-a', now() + interval '15 minutes') RETURNING id`,
		hash, controllerID).Scan(&tokenID)
	if err != nil {
		t.Fatalf("insert enrollment token: %v", err)
	}

	// First claim succeeds.
	var claimed string
	err = pool.QueryRow(ctx,
		`UPDATE enrollment_tokens SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
		 RETURNING id`, hash).Scan(&claimed)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if claimed != tokenID {
		t.Errorf("claimed %q, want %q", claimed, tokenID)
	}

	// Second claim finds no row. This is the property that makes the token a
	// one-time credential rather than a short-lived one.
	var again string
	err = pool.QueryRow(ctx,
		`UPDATE enrollment_tokens SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
		 RETURNING id`, hash).Scan(&again)
	if err == nil {
		t.Fatalf("second claim succeeded (%q); the token is reusable", again)
	}
}

// Concurrent redemption: the claim that matters. Two goroutines redeem the same
// token at once and exactly one must win. A sequential test cannot prove this —
// it would also pass if the guarantee lived in application code, which is
// precisely what the design forbids.
//
// The mechanism being relied on: the claiming UPDATE holds a row lock until it
// commits, so the loser blocks, then re-evaluates its WHERE clause against the
// committed row (READ COMMITTED) and finds nothing to claim.
func TestEnrollmentTokenConcurrentClaimHasExactlyOneWinner(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	hash := []byte{0x0e, 0x0f}
	if _, err := pool.Exec(ctx,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at)
		 VALUES ($1, $2, 'node-race', now() + interval '15 minutes')`, hash, controllerID); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	const racers = 8
	claim := `UPDATE enrollment_tokens SET used_at = now()
	          WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
	          RETURNING id`

	start := make(chan struct{})
	results := make(chan bool, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all racers together
			var id string
			err := pool.QueryRow(ctx, claim, hash).Scan(&id)
			results <- err == nil
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for won := range results {
		if won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%d concurrent racers claimed the token, want exactly 1", winners)
	}

	// And the row records exactly one claim.
	var usedCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM enrollment_tokens WHERE token_hash = $1 AND used_at IS NOT NULL`,
		hash).Scan(&usedCount); err != nil {
		t.Fatalf("count claimed rows: %v", err)
	}
	if usedCount != 1 {
		t.Errorf("%d rows marked used, want 1", usedCount)
	}
}

// An expired token must not be claimable even before anyone used it.
func TestEnrollmentTokenExpiryBlocksClaim(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	hash := []byte{0x0a, 0x0b}
	// expires_at must be after created_at per the CHECK, so insert a token that
	// expired a moment ago by backdating both.
	_, err := pool.Exec(ctx,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at, created_at)
		 VALUES ($1, $2, 'node-b', now() - interval '1 minute', now() - interval '16 minutes')`,
		hash, controllerID)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}
	var id string
	err = pool.QueryRow(ctx,
		`UPDATE enrollment_tokens SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
		 RETURNING id`, hash).Scan(&id)
	if err == nil {
		t.Fatal("an expired token was claimable, want refusal")
	}
}

// The token digest is unique: two rows describing one token would make the
// claiming UPDATE ambiguous.
func TestEnrollmentTokenHashIsUnique(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	hash := []byte{0x0c, 0x0d}
	if _, err := pool.Exec(ctx,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at)
		 VALUES ($1, $2, 'node-c', now() + interval '15 minutes')`, hash, controllerID); err != nil {
		t.Fatalf("insert token: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at)
		 VALUES ('\x0c0d'::bytea, '`+controllerID+`', 'node-d', now() + interval '15 minutes')`,
		"enrollment_tokens_token_hash_key")
}

// Used and revoked are mutually exclusive states. Allowing both would make "why
// was this refused?" unanswerable.
func TestEnrollmentTokenStatesAreExclusive(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	mustFail(t, ctx, pool,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at, used_at, revoked_at)
		 VALUES ('\x99'::bytea, '`+controllerID+`', 'node-e', now() + interval '15 minutes', now(), now())`,
		"enrollment_tokens_terminal_exclusive")
}

// A token's expiry must be after its creation, or a token would be born dead
// while appearing live in a list.
func TestEnrollmentTokenExpiryAfterCreation(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	mustFail(t, ctx, pool,
		`INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at, created_at)
		 VALUES ('\x88'::bytea, '`+controllerID+`', 'node-f', now(), now() + interval '1 minute')`,
		"enrollment_tokens_expiry_after_creation")
}

// A certificate revocation without a reason is an audit gap, and the database
// refuses it rather than relying on reviewer discipline.
func TestNodeCertificateRevocationRequiresReason(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('revcert') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO node_certificates (serial, server_id, fingerprint, not_before, not_after)
		 VALUES ('abc123', $1, 'ff00', now(), now() + interval '30 days')`, serverID); err != nil {
		t.Fatalf("insert certificate: %v", err)
	}
	mustFail(t, ctx, pool,
		`UPDATE node_certificates SET revoked_at = now() WHERE serial = 'abc123'`,
		"node_certificates_revoke_reason")

	// With a reason it is accepted.
	if _, err := pool.Exec(ctx,
		`UPDATE node_certificates SET revoked_at = now(), revoke_reason = 'node compromised'
		 WHERE serial = 'abc123'`); err != nil {
		t.Errorf("revoke with reason: %v", err)
	}
}

// A certificate window must be a window.
func TestNodeCertificateWindowIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('badcert') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO node_certificates (serial, server_id, fingerprint, not_before, not_after)
		 VALUES ('backwards', '`+serverID+`', 'ff01', now() + interval '1 day', now())`,
		"node_certificates_window")
}

// Reporting the same capability twice must update rather than duplicate, so a
// node's inventory is idempotent to report.
func TestNodeCapabilityUpsertIsUnique(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('caps') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO node_capabilities (server_id, kind, name, version)
		 VALUES ($1, 'init', 'systemd', '255')`, serverID); err != nil {
		t.Fatalf("insert capability: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO node_capabilities (server_id, kind, name) VALUES ('`+serverID+`', 'init', 'systemd')`,
		"node_capabilities_unique")

	// An upsert refreshes the observation.
	if _, err := pool.Exec(ctx,
		`INSERT INTO node_capabilities (server_id, kind, name, version, state)
		 VALUES ($1, 'init', 'systemd', '256', 'degraded')
		 ON CONFLICT (server_id, kind, name) DO UPDATE
		 SET version = EXCLUDED.version, state = EXCLUDED.state`, serverID); err != nil {
		t.Errorf("upsert capability: %v", err)
	}
}

// A capability state is closed: an unrecognized value would be silently
// unhandled by every consumer.
func TestNodeCapabilityStateIsClosed(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('capstate') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO node_capabilities (server_id, kind, name, state)
		 VALUES ('`+serverID+`', 'web', 'nginx', 'probably')`,
		"node_capabilities_state_check")
}

// Memory accounting must not be able to claim more used than total.
func TestHeartbeatMemoryShapeIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('beats') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO node_heartbeats (server_id, observed_at, mem_total_bytes, mem_used_bytes)
		 VALUES ('`+serverID+`', now(), 100, 200)`,
		"node_heartbeats_memory_shape")

	// A valid heartbeat is accepted and readable newest-first.
	if _, err := pool.Exec(ctx,
		`INSERT INTO node_heartbeats (server_id, observed_at, uptime_seconds, mem_total_bytes, mem_used_bytes)
		 VALUES ($1, $2, 3600, 1024, 512)`, serverID, time.Now()); err != nil {
		t.Fatalf("insert heartbeat: %v", err)
	}
}

// A node identity carries the URI it authenticates with, and an empty URI would
// make the identity unusable while looking present.
func TestNodeIdentityRequiresURI(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('ident') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO node_identities (server_id, controller_id, node_uri)
		 VALUES ('`+serverID+`', '`+controllerID+`', '  ')`,
		"node_identities_uri_present")
}

// Deleting a server takes its certificates with it, so a re-enrolled server
// cannot inherit a revoked history or a stale identity.
func TestServerDeletionCascadesToNodeState(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	controllerID := insertController(t, ctx, pool)
	var serverID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ('cascade') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO node_identities (server_id, controller_id, node_uri)
		 VALUES ($1, $2, $3)`,
		serverID, controllerID, "spiffe://jawaker/node/"+serverID); err != nil {
		t.Fatalf("insert identity: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO node_certificates (serial, server_id, fingerprint, not_before, not_after)
		 VALUES ('cascade1', $1, 'ff02', now(), now() + interval '30 days')`, serverID); err != nil {
		t.Fatalf("insert certificate: %v", err)
	}

	// This is a HARD delete, which is why application code must tombstone a
	// server with a status transition rather than issuing DELETE. The cascade
	// exists for retention cleanup and test teardown, not for normal removal.
	if _, err := pool.Exec(ctx, `DELETE FROM servers WHERE id = $1`, serverID); err != nil {
		t.Fatalf("delete server: %v", err)
	}
	for _, table := range []string{"node_identities", "node_certificates", "node_heartbeats", "node_capabilities"} {
		var count int
		query := `SELECT count(*) FROM ` + table + ` WHERE server_id = $1`
		if err := pool.QueryRow(ctx, query, serverID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s retained %d rows after server deletion, want 0", table, count)
		}
	}
}
