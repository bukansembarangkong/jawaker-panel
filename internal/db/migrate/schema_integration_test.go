//go:build integration

// Integration tests that apply the REAL control-plane migration set
// (migrations.FS) to a live PostgreSQL and pin the database-level invariants
// Phase 1 application code is allowed to assume.
//
// These are not a substitute for application tests. They exist so a later
// migration that quietly drops a trigger, a CHECK, or a partial unique index
// fails CI instead of silently weakening immutability, idempotency, or the
// single-owner guarantee (SECURITY.md §5, DATABASE.md §10-11, §16).
//
// Run with:
//
//	JAWAKER_TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/db/migrate/

package migrate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyRealMigrations resets the public schema and applies the embedded
// migration set, asserting it applied cleanly and completely.
func applyRealMigrations(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool := freshPool(t)

	m, err := New(migrations.FS, testLogger())
	if err != nil {
		t.Fatalf("New(migrations.FS): %v", err)
	}
	want := len(m.Migrations())
	if want == 0 {
		t.Fatal("migrations.FS contains no migrations")
	}

	applied, err := m.Up(ctx, pool)
	if err != nil {
		t.Fatalf("Up(real migrations): %v", err)
	}
	if len(applied) != want {
		t.Errorf("applied %d migrations %v, want %d", len(applied), applied, want)
	}

	// A second run must be a no-op: proves checksums are stable and the seed
	// migration does not violate its own uniqueness on re-application.
	again, err := m.Up(ctx, pool)
	if err != nil {
		t.Fatalf("second Up(real migrations): %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second Up applied %v, want none", again)
	}
	return pool
}

// mustFail asserts the statement is rejected and the error mentions substr.
func mustFail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label, want string, args ...any) {
	t.Helper()
	_, err := pool.Exec(ctx, label, args...)
	if err == nil {
		t.Fatalf("%s: statement accepted, want rejection containing %q", label, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: error %q should mention %q", label, err, want)
	}
}

func TestRealMigrationsCreatePhase1Tables(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	for _, table := range []string{
		"schema_migrations",
		// identity
		"users", "password_credentials", "sessions", "totp_credentials", "recovery_codes",
		// rbac
		"permissions", "roles", "role_permissions", "role_bindings",
		// audit / revisions
		"audit_events", "revisions",
		// jobs
		"jobs", "job_resource_locks", "job_steps", "job_attempts",
		// notifications
		"notification_channels", "notification_routes", "notification_deliveries", "notification_reads",
	} {
		if !tableExists(ctx, pool, table) {
			t.Errorf("table %q missing after migrations", table)
		}
	}
}

// insertUser creates a user and returns its id. accountType/isOwner mirror the
// coarse account class; the RBAC tables carry the granular authority.
func insertUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string, isOwner bool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO users (email, display_name, is_owner)
		 VALUES ($1, $2, $3) RETURNING id`,
		email, "Test User", isOwner).Scan(&id)
	if err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
	return id
}

func TestUsersSingleOwnerEnforcedByDatabase(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	insertUser(t, ctx, pool, "owner@example.test", true)
	// A second owner must be impossible even under a concurrent bootstrap race;
	// the partial unique index is the authority, not application logic.
	mustFail(t, ctx, pool,
		`INSERT INTO users (email, display_name, is_owner) VALUES ('owner2@example.test', 'Second', true)`,
		"users_single_owner_idx")

	// Non-owners are unrestricted.
	insertUser(t, ctx, pool, "not-owner@example.test", false)
}

func TestUsersEmailIsCaseInsensitiveUnique(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	insertUser(t, ctx, pool, "MixedCase@Example.test", false)
	mustFail(t, ctx, pool,
		`INSERT INTO users (email, display_name) VALUES ('mixedcase@example.TEST', 'Dup')`,
		"users_email_key")
}

func TestPasswordCredentialSingleActivePerUser(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	userID := insertUser(t, ctx, pool, "pw@example.test", false)

	if _, err := pool.Exec(ctx,
		`INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA')`,
		userID); err != nil {
		t.Fatalf("insert first credential: %v", err)
	}
	// Two ACTIVE credentials would make verification ambiguous.
	mustFail(t, ctx, pool,
		`INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaDI')`,
		"password_credentials_active_idx", userID)

	// Superseding the first makes room for exactly one active row again.
	if _, err := pool.Exec(ctx,
		`UPDATE password_credentials SET superseded_at = now() WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaDM')`,
		userID); err != nil {
		t.Fatalf("insert rotated credential: %v", err)
	}
}

func TestSessionsTokenHashIsUnique(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	userID := insertUser(t, ctx, pool, "sess@example.test", false)
	insert := `INSERT INTO sessions (user_id, token_hash, absolute_expires_at, idle_expires_at)
	           VALUES ($1, decode($2, 'hex'), now() + interval '30 days', now() + interval '1 hour')`

	// 32-byte SHA-256 hash of a session token. The raw token is never stored.
	hash := strings.Repeat("ab", 32)
	if _, err := pool.Exec(ctx, insert, userID, hash); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	// A replayed token hash must not create a second live session.
	mustFail(t, ctx, pool, insert, "sessions_token_hash_key", userID, hash)
}

func TestAuditEventsRejectUpdateAndDelete(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_events (actor_type, action, resource_type, resource_id, result, request_id)
		 VALUES ('system', 'site.create', 'site', 'site-1', 'success', 'req_audit_1')`); err != nil {
		t.Fatalf("insert audit event: %v", err)
	}

	// Append-only by trigger: a bug in application code cannot rewrite history.
	mustFail(t, ctx, pool,
		`UPDATE audit_events SET result = 'denied' WHERE request_id = 'req_audit_1'`,
		"append-only")
	mustFail(t, ctx, pool,
		`DELETE FROM audit_events WHERE request_id = 'req_audit_1'`,
		"append-only")

	// Inserts still work, and the row survived both attempts.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE request_id = 'req_audit_1'`).Scan(&count); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if count != 1 {
		t.Errorf("audit row count = %d, want 1", count)
	}

	// The CHECK constraints are part of the contract too.
	mustFail(t, ctx, pool,
		`INSERT INTO audit_events (actor_type, action, resource_type, result)
		 VALUES ('ghost', 'x.y', 'x', 'success')`,
		"actor_type")
	mustFail(t, ctx, pool,
		`INSERT INTO audit_events (actor_type, action, resource_type, result)
		 VALUES ('system', 'x.y', 'x', 'maybe')`,
		"result")
}

func TestRevisionsProtectSubstanceButAllowProgress(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var revID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO revisions (resource_type, resource_id, actor_type, candidate, candidate_hash)
		 VALUES ('site', 'site-1', 'system', '{"domain":"example.test"}'::jsonb, 'hash-1')
		 RETURNING id`).Scan(&revID); err != nil {
		t.Fatalf("insert revision: %v", err)
	}

	// Lifecycle columns are filled in as the change progresses — allowed.
	if _, err := pool.Exec(ctx,
		`UPDATE revisions SET state = 'validated', validation_result = '{"ok":true}'::jsonb WHERE id = $1`,
		revID); err != nil {
		t.Fatalf("update revision state: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE revisions SET state = 'applied', applied_at = now(), git_sync_state = 'not_required' WHERE id = $1`,
		revID); err != nil {
		t.Fatalf("update revision progress: %v", err)
	}

	// The substance of a historical revision is immutable — a corrected change
	// must be a NEW revision, so the trail can be replayed.
	mustFail(t, ctx, pool,
		`UPDATE revisions SET candidate = '{"domain":"evil.test"}'::jsonb WHERE id = $1`,
		"immutable", revID)
	mustFail(t, ctx, pool,
		`UPDATE revisions SET candidate_hash = 'hash-2' WHERE id = $1`,
		"immutable", revID)
	mustFail(t, ctx, pool,
		`UPDATE revisions SET resource_id = 'site-2' WHERE id = $1`,
		"immutable", revID)

	// State CHECK still constrains the lifecycle vocabulary.
	mustFail(t, ctx, pool,
		`UPDATE revisions SET state = 'partly-applied' WHERE id = $1`,
		"state", revID)
}

func TestRoleBindingScopeShapeIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	userID := insertUser(t, ctx, pool, "bind@example.test", false)
	var roleID string
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE key = 'viewer'`).Scan(&roleID); err != nil {
		t.Fatalf("lookup viewer role: %v", err)
	}

	// Global bindings must not carry a scope id; ambiguous scopes would make
	// authorization decisions unanswerable.
	mustFail(t, ctx, pool,
		`INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id)
		 VALUES ($1, $2, 'global', gen_random_uuid())`,
		"role_bindings_scope_shape", userID, roleID)
	// Scoped bindings must carry one.
	mustFail(t, ctx, pool,
		`INSERT INTO role_bindings (user_id, role_id, scope_type) VALUES ($1, $2, 'project')`,
		"role_bindings_scope_shape", userID, roleID)

	// A well-formed binding inserts, and the duplicate is rejected while active.
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_bindings (user_id, role_id, scope_type) VALUES ($1, $2, 'global')`,
		userID, roleID); err != nil {
		t.Fatalf("insert global binding: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO role_bindings (user_id, role_id, scope_type) VALUES ($1, $2, 'global')`,
		"role_bindings_unique_idx", userID, roleID)

	// Revoking frees the slot for a re-grant (history is kept, not overwritten).
	if _, err := pool.Exec(ctx,
		`UPDATE role_bindings SET revoked_at = now() WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("revoke binding: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_bindings (user_id, role_id, scope_type) VALUES ($1, $2, 'global')`,
		userID, roleID); err != nil {
		t.Fatalf("re-grant after revoke: %v", err)
	}
}

func TestRBACSeedIsSane(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var permCount, roleCount, grantCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions`).Scan(&permCount); err != nil {
		t.Fatalf("count permissions: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE is_builtin`).Scan(&roleCount); err != nil {
		t.Fatalf("count builtin roles: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions`).Scan(&grantCount); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if permCount < 50 {
		t.Errorf("permissions = %d, want the full catalog (>= 50)", permCount)
	}
	if roleCount != 9 {
		t.Errorf("builtin roles = %d, want 9", roleCount)
	}
	if grantCount < permCount {
		t.Errorf("grants = %d, want at least the catalog size (%d)", grantCount, permCount)
	}

	// No built-in role may be empty: an empty role silently denies everything
	// and looks identical to a missing seed.
	var empty int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM roles r
		WHERE r.is_builtin
		  AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id)`).Scan(&empty); err != nil {
		t.Fatalf("count empty roles: %v", err)
	}
	if empty != 0 {
		t.Errorf("%d built-in roles have no permissions; seed is incomplete", empty)
	}

	// Platform Owner is expressed as an explicit grant of the WHOLE catalog, so
	// "what can the owner do?" stays answerable by querying the tables rather
	// than by a magic superuser flag in code.
	var ownerGrants int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.key = 'platform_owner'`).Scan(&ownerGrants); err != nil {
		t.Fatalf("count owner grants: %v", err)
	}
	if ownerGrants != permCount {
		t.Errorf("platform_owner grants = %d, want %d (full catalog)", ownerGrants, permCount)
	}

	// Read-only viewer must hold ONLY read permissions — a leaked write grant
	// here is a privilege escalation.
	var viewerNonRead int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.key = 'viewer' AND rp.permission_key NOT LIKE '%.read'`).Scan(&viewerNonRead); err != nil {
		t.Fatalf("count viewer non-read grants: %v", err)
	}
	if viewerNonRead != 0 {
		t.Errorf("viewer holds %d non-read permissions, want 0", viewerNonRead)
	}

	// Operator may monitor but never mutate configuration.
	var operatorMutations int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.key = 'operator'
		  AND rp.permission_key IN ('server.manage', 'site.manage', 'firewall.manage', 'users.manage')`).
		Scan(&operatorMutations); err != nil {
		t.Fatalf("count operator mutation grants: %v", err)
	}
	if operatorMutations != 0 {
		t.Errorf("operator holds %d mutation permissions, want 0", operatorMutations)
	}

	// Step-up requirement must be declared for the destructive catalog entries.
	var missingStepUp int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM permissions
		WHERE requires_step_up = false
		  AND key IN ('server.delete', 'project.delete', 'site.delete', 'database.delete',
		              'backup.restore', 'firewall.manage', 'terminal.root')`).Scan(&missingStepUp); err != nil {
		t.Fatalf("count permissions missing step-up: %v", err)
	}
	if missingStepUp != 0 {
		t.Errorf("%d destructive permissions lack requires_step_up", missingStepUp)
	}
}

func TestJobsIdempotencyKeyIsEnforcedByDatabase(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	enqueue := `INSERT INTO jobs (type, idempotency_key, idempotency_scope) VALUES ($1, $2, $3)`

	if _, err := pool.Exec(ctx, enqueue, "site.create", "key-1", "user:1"); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	// A retried HTTP request must not double-enqueue the same work.
	mustFail(t, ctx, pool, enqueue, "jobs_idempotency_idx", "site.create", "key-1", "user:1")

	// The same key under a different scope is different work.
	if _, err := pool.Exec(ctx, enqueue, "site.create", "key-1", "user:2"); err != nil {
		t.Fatalf("enqueue same key different scope: %v", err)
	}
	// Jobs without an idempotency key are unrestricted (internal/scheduled).
	if _, err := pool.Exec(ctx, enqueue, "metrics.scrape", nil, nil); err != nil {
		t.Fatalf("enqueue without key: %v", err)
	}
	if _, err := pool.Exec(ctx, enqueue, "metrics.scrape", nil, nil); err != nil {
		t.Fatalf("second enqueue without key: %v", err)
	}

	// State CHECK keeps the lifecycle vocabulary closed.
	mustFail(t, ctx, pool,
		`INSERT INTO jobs (type, state) VALUES ('x', 'half-done')`,
		"state")
}

func TestJobResourceLocksAreExclusive(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var jobA, jobB string
	if err := pool.QueryRow(ctx, `INSERT INTO jobs (type) VALUES ('site.update') RETURNING id`).Scan(&jobA); err != nil {
		t.Fatalf("insert job A: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO jobs (type) VALUES ('site.update') RETURNING id`).Scan(&jobB); err != nil {
		t.Fatalf("insert job B: %v", err)
	}

	// Two jobs must not mutate one resource at once.
	if _, err := pool.Exec(ctx,
		`INSERT INTO job_resource_locks (lock_key, job_id) VALUES ('site:1', $1)`, jobA); err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	mustFail(t, ctx, pool,
		`INSERT INTO job_resource_locks (lock_key, job_id) VALUES ('site:1', $1)`,
		"job_resource_locks_pkey", jobB)

	// Releasing lets the next job in; deleting the job cascades the lock so a
	// crashed-and-pruned job can never strand a resource.
	if _, err := pool.Exec(ctx, `DELETE FROM job_resource_locks WHERE lock_key = 'site:1'`); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO job_resource_locks (lock_key, job_id) VALUES ('site:1', $1)`, jobB); err != nil {
		t.Fatalf("reacquire lock: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM jobs WHERE id = $1`, jobB); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM job_resource_locks WHERE lock_key = 'site:1'`).Scan(&remaining); err != nil {
		t.Fatalf("count locks: %v", err)
	}
	if remaining != 0 {
		t.Errorf("lock survived job deletion (count=%d), want cascade", remaining)
	}
}

func TestJobStepsUniquePerJob(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var jobID string
	if err := pool.QueryRow(ctx, `INSERT INTO jobs (type) VALUES ('site.create') RETURNING id`).Scan(&jobID); err != nil {
		t.Fatalf("insert job: %v", err)
	}

	insert := `INSERT INTO job_steps (job_id, step_index, name) VALUES ($1, 0, 'validate')`
	if _, err := pool.Exec(ctx, insert, jobID); err != nil {
		t.Fatalf("insert step: %v", err)
	}
	// Duplicate step indexes would corrupt progress reporting and resume order.
	mustFail(t, ctx, pool, insert, "job_steps_job_id_step_index_key", jobID)
}

func TestNotificationRoutesAreUniquePerUserChannel(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	userID := insertUser(t, ctx, pool, "notify@example.test", false)
	var channelID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_channels (type, name) VALUES ('in_panel', 'Inbox') RETURNING id`).
		Scan(&channelID); err != nil {
		t.Fatalf("insert channel: %v", err)
	}

	insert := `INSERT INTO notification_routes (user_id, channel_id) VALUES ($1, $2)`
	if _, err := pool.Exec(ctx, insert, userID, channelID); err != nil {
		t.Fatalf("insert route: %v", err)
	}
	mustFail(t, ctx, pool, insert, "notification_routes_unique_idx", userID, channelID)
}

func TestNotificationDeliverySeverityAndStateAreClosed(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var channelID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_channels (type, name) VALUES ('in_panel', 'Inbox') RETURNING id`).
		Scan(&channelID); err != nil {
		t.Fatalf("insert channel: %v", err)
	}

	mustFail(t, ctx, pool,
		`INSERT INTO notification_deliveries (event, severity, channel_id) VALUES ('x.y', 'urgent', $1)`,
		"severity", channelID)
	mustFail(t, ctx, pool,
		`INSERT INTO notification_deliveries (event, severity, channel_id, state) VALUES ('x.y', 'info', $1, 'sent')`,
		"state", channelID)

	// A valid delivery with bounded retention inserts cleanly.
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_deliveries (event, severity, channel_id, dedup_key, expires_at)
		 VALUES ('backup.failed', 'critical', $1, 'backup:plan-1', now() + interval '30 days')`,
		channelID); err != nil {
		t.Fatalf("insert delivery: %v", err)
	}
}
