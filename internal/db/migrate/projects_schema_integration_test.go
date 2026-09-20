//go:build integration

// Integration tests for the Phase 3 projects/sites schema (migrations 0014 and
// 0015), applied through the REAL migration set against live PostgreSQL.
//
// These pin the invariants the Go code is allowed to assume. Each one is a
// constraint that exists because the alternative is a silent failure, so a test
// that merely asserts "the table exists" would not be testing the thing the
// migration was written for.
//
// The three that matter most:
//
//   * ONE LIVE SITE PER HOSTNAME, installation-wide. Two sites claiming
//     example.com is not a config mistake a human notices; it makes "which site
//     answered this request?" unanswerable after the fact.
//   * TENANT TRACEABILITY. sites.project_id is NOT NULL, so there is no
//     inferred ownership chain for an authorization query to get wrong
//     (DATABASE.md §6).
//   * TOMBSTONES. A deleted site keeps its row so the revision and audit rows
//     that reference it stay resolvable (DATABASE.md §7).

package migrate

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// insertProject creates a live project and returns its id.
func insertProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name) VALUES ($1, $2) RETURNING id`,
		slug, "Project "+slug).Scan(&id)
	if err != nil {
		t.Fatalf("insert project %s: %v", slug, err)
	}
	return id
}

// insertServer creates a server row standalone. Phase 2's servers table has no
// controller FK, so a project/site test needs no enrollment machinery.
func insertServer(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO servers (name) VALUES ($1) RETURNING id`, name).Scan(&id)
	if err != nil {
		t.Fatalf("insert server %s: %v", name, err)
	}
	return id
}

// insertSite creates a static site and returns its id.
func insertSite(t *testing.T, ctx context.Context, pool *pgxpool.Pool, projectID, serverID, slug string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO sites (project_id, server_id, slug, name, mode)
		 VALUES ($1, $2, $3, $4, 'static') RETURNING id`,
		projectID, serverID, slug, "Site "+slug).Scan(&id)
	if err != nil {
		t.Fatalf("insert site %s: %v", slug, err)
	}
	return id
}

func TestRealMigrationsCreatePhase3Tables(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	for _, table := range []string{
		"projects",
		"project_memberships",
		"project_quotas",
		"sites",
		"site_domains",
		"certificates",
		"domain_certificates",
	} {
		if !tableExists(ctx, pool, table) {
			t.Errorf("table %q missing after migrations", table)
		}
	}
}

// A project slug is a directory name and a Unix group name, so the constraint
// on its alphabet is the first defence against a slug that is really a path
// fragment. This test exists because the CHECK could be dropped and nothing else
// would notice until the filesystem code trusted it.
func TestProjectSlugAlphabetIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	insertProject(t, ctx, pool, "acme")

	for _, bad := range []string{
		"../../etc/passwd", // traversal
		"acme/../other",    // traversal by another shape
		"ACME",             // uppercase
		"-acme",            // leading hyphen
		"acme-",            // trailing hyphen
		"acme_corp",        // underscore
		"acme corp",        // space
	} {
		mustFail(t, ctx, pool,
			`INSERT INTO projects (slug, name) VALUES ($1, 'x')`,
			"projects_slug_safe", bad)
	}

	// Length is a separate constraint, so it is asserted separately. Both cases
	// are WELL-FORMED slugs that differ only in length; a filler string would
	// also violate the alphabet, and PostgreSQL does not guarantee which
	// constraint it reports first, so the assertion would be unreliable.
	for _, bad := range []string{"ab", strings.Repeat("a", 49)} {
		mustFail(t, ctx, pool,
			`INSERT INTO projects (slug, name) VALUES ($1, 'x')`,
			"projects_slug_length", bad)
	}
}

// Slug uniqueness applies only to live projects, so a tombstoned project keeps
// its slug readable without blocking reuse.
func TestProjectSlugUniqueAmongLiveOnly(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	id := insertProject(t, ctx, pool, "acme")

	mustFail(t, ctx, pool,
		`INSERT INTO projects (slug, name) VALUES ('acme', 'Second')`,
		"projects_slug_unique_idx")

	// Tombstone the first, then the slug is free again.
	if _, err := pool.Exec(ctx,
		`UPDATE projects SET state = 'deleted', deleted_at = now() WHERE id = $1`, id); err != nil {
		t.Fatalf("tombstone project: %v", err)
	}
	insertProject(t, ctx, pool, "acme")
}

// A deleted project must carry a deletion time and a live one must not: without
// this, "is this project gone?" has two answers depending on which column a
// caller happens to read.
func TestProjectDeletedShapeIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	mustFail(t, ctx, pool,
		`INSERT INTO projects (slug, name, state) VALUES ('acme', 'x', 'deleted')`,
		"projects_deleted_shape")

	mustFail(t, ctx, pool,
		`INSERT INTO projects (slug, name, deleted_at) VALUES ('acme', 'x', now())`,
		"projects_deleted_shape")
}

// pending_delete must carry a deadline, because the grace period is measured
// from it and an inference from updated_at would move whenever the row is
// touched.
func TestProjectPendingDeleteRequiresDeadline(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	mustFail(t, ctx, pool,
		`INSERT INTO projects (slug, name, state) VALUES ('acme', 'x', 'pending_delete')`,
		"projects_delete_after_shape")

	if _, err := pool.Exec(ctx,
		`INSERT INTO projects (slug, name, state, delete_after)
		 VALUES ('acme', 'x', 'pending_delete', now() + interval '7 days')`); err != nil {
		t.Fatalf("pending_delete with a deadline: %v", err)
	}
}

// The tenant boundary: a site cannot exist without a project.
func TestSiteRequiresProject(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	serverID := insertServer(t, ctx, pool, "node-1")

	mustFail(t, ctx, pool,
		`INSERT INTO sites (server_id, slug, name, mode) VALUES ($1, 'www', 'x', 'static')`,
		"null value in column \"project_id\"", serverID)

	// A site naming a project that does not exist is refused by the FK rather
	// than becoming an orphan with an unresolvable owner.
	mustFail(t, ctx, pool,
		`INSERT INTO sites (project_id, server_id, slug, name, mode)
		 VALUES ('00000000-0000-0000-0000-000000000000', $1, 'www', 'x', 'static')`,
		"sites_project_id_fkey", serverID)
}

// Two projects may each have a site slugged "www"; the path disambiguates by
// project. This is the constraint that makes that safe.
func TestSiteSlugUniquePerProjectNotGlobally(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	serverID := insertServer(t, ctx, pool, "node-1")
	p1 := insertProject(t, ctx, pool, "acme")
	p2 := insertProject(t, ctx, pool, "globex")

	insertSite(t, ctx, pool, p1, serverID, "www")

	// Same slug in a DIFFERENT project is allowed.
	insertSite(t, ctx, pool, p2, serverID, "www")

	// Same slug in the SAME project is not.
	mustFail(t, ctx, pool,
		`INSERT INTO sites (project_id, server_id, slug, name, mode)
		 VALUES ($1, $2, 'www', 'x', 'static')`,
		"sites_slug_unique_idx", p1, serverID)
}

// A site cannot be attached to a server that does not exist, and deleting the
// server is refused while sites still reference it — the operator must move
// them first, which is the moment they should be thinking about it.
func TestSiteServerReferenceIsRestrictive(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")
	insertSite(t, ctx, pool, projectID, serverID, "www")

	mustFail(t, ctx, pool,
		`DELETE FROM servers WHERE id = $1`,
		"sites_server_id_fkey", serverID)
}

// A static site with an upstream, or a reverse_proxy site without one, is a row
// whose meaning nobody can state — and it would render a proxy_pass block for a
// site that has no upstream to reach.
func TestSiteModeFieldsMustAgreeWithMode(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")

	// static with an upstream: refused.
	mustFail(t, ctx, pool,
		`INSERT INTO sites (project_id, server_id, slug, name, mode, upstream)
		 VALUES ($1, $2, 'a', 'x', 'static', 'http://127.0.0.1:3000')`,
		"sites_upstream_matches_mode", projectID, serverID)

	// reverse_proxy without one: refused.
	mustFail(t, ctx, pool,
		`INSERT INTO sites (project_id, server_id, slug, name, mode)
		 VALUES ($1, $2, 'b', 'x', 'reverse_proxy')`,
		"sites_upstream_matches_mode", projectID, serverID)

	// Both consistent: accepted.
	if _, err := pool.Exec(ctx,
		`INSERT INTO sites (project_id, server_id, slug, name, mode, upstream)
		 VALUES ($1, $2, 'c', 'x', 'reverse_proxy', 'http://127.0.0.1:3000')`,
		projectID, serverID); err != nil {
		t.Fatalf("reverse_proxy with an upstream: %v", err)
	}

	// A php_unit on a non-php site is refused.
	mustFail(t, ctx, pool,
		`INSERT INTO sites (project_id, server_id, slug, name, mode, php_unit)
		 VALUES ($1, $2, 'd', 'x', 'static', 'php8.3-fpm')`,
		"sites_php_unit_matches_mode", projectID, serverID)
}

// An unknown mode is refused at the schema, so a mode added by a later phase is
// a deliberate migration rather than an accidental string.
func TestSiteModeIsBounded(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")

	for _, mode := range []string{"container", "apache", "STATIC", ""} {
		mustFail(t, ctx, pool,
			`INSERT INTO sites (project_id, server_id, slug, name, mode)
			 VALUES ($1, $2, 'x', 'y', $3)`,
			"sites_mode_check", projectID, serverID, mode)
	}
}

// THE ROUTING-AMBIGUITY CONSTRAINT: one live site per hostname across the whole
// installation, even when the two sites belong to different projects.
func TestHostnameIsUniqueAcrossTheInstallation(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	serverID := insertServer(t, ctx, pool, "node-1")
	p1 := insertProject(t, ctx, pool, "acme")
	p2 := insertProject(t, ctx, pool, "globex")
	s1 := insertSite(t, ctx, pool, p1, serverID, "www")
	s2 := insertSite(t, ctx, pool, p2, serverID, "www")

	if _, err := pool.Exec(ctx,
		`INSERT INTO site_domains (site_id, hostname, is_primary) VALUES ($1, 'example.com', true)`,
		s1); err != nil {
		t.Fatalf("first hostname claim: %v", err)
	}

	// A DIFFERENT project claiming the same hostname must fail. Project
	// isolation does not make the routing ambiguity disappear.
	mustFail(t, ctx, pool,
		`INSERT INTO site_domains (site_id, hostname, is_primary) VALUES ($1, 'example.com', true)`,
		"site_domains_hostname_unique_idx", s2)
}

// Hostname syntax is constrained in the schema because the string is written
// into a generated config file and used as a certificate identifier. A hostname
// is never free text.
func TestHostnameSyntaxIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")
	siteID := insertSite(t, ctx, pool, projectID, serverID, "www")

	for _, bad := range []string{
		"Example.com",                       // uppercase
		"example.com.",                      // trailing dot
		"localhost",                         // single label
		"example..com",                      // empty label
		"-example.com",                      // leading hyphen in a label
		"example.com:443",                   // port
		"https://example.com",               // scheme
		"example.com/path",                  // path
		"*.example.com",                     // wildcard is not a hostname
		"example.com\nserver_name evil.com", // injected line
		"exa mple.com",                      // space
	} {
		mustFail(t, ctx, pool,
			`INSERT INTO site_domains (site_id, hostname) VALUES ($1, $2)`,
			"site_domains_hostname_syntax", siteID, bad)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO site_domains (site_id, hostname, is_primary) VALUES ($1, 'www.example.com', true)`,
		siteID); err != nil {
		t.Fatalf("valid hostname: %v", err)
	}
}

// At most one primary hostname per site: two primaries makes "which name
// redirects to the canonical one?" unanswerable.
func TestAtMostOnePrimaryHostnamePerSite(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")
	siteID := insertSite(t, ctx, pool, projectID, serverID, "www")

	if _, err := pool.Exec(ctx,
		`INSERT INTO site_domains (site_id, hostname, is_primary) VALUES ($1, 'example.com', true)`,
		siteID); err != nil {
		t.Fatalf("first primary: %v", err)
	}

	mustFail(t, ctx, pool,
		`INSERT INTO site_domains (site_id, hostname, is_primary) VALUES ($1, 'www.example.com', true)`,
		"site_domains_primary_unique_idx", siteID)

	// A non-primary alias on the same site is fine.
	if _, err := pool.Exec(ctx,
		`INSERT INTO site_domains (site_id, hostname, is_primary) VALUES ($1, 'www.example.com', false)`,
		siteID); err != nil {
		t.Fatalf("non-primary alias: %v", err)
	}
}

// A tombstoned hostname releases the name, which is what a re-created site
// depends on.
func TestTombstonedHostnameReleasesTheName(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")
	siteID := insertSite(t, ctx, pool, projectID, serverID, "www")

	if _, err := pool.Exec(ctx,
		`INSERT INTO site_domains (site_id, hostname) VALUES ($1, 'example.com')`,
		siteID); err != nil {
		t.Fatalf("claim hostname: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE site_domains SET deleted_at = now() WHERE site_id = $1`, siteID); err != nil {
		t.Fatalf("tombstone hostname: %v", err)
	}

	other := insertSite(t, ctx, pool, projectID, serverID, "other")
	if _, err := pool.Exec(ctx,
		`INSERT INTO site_domains (site_id, hostname) VALUES ($1, 'example.com')`,
		other); err != nil {
		t.Fatalf("reclaim tombstoned hostname: %v", err)
	}
}

// A certificate inventory row carries a SECRET REFERENCE and never key
// material, and an inverted validity window is refused.
func TestCertificateWindowAndSecretReference(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")

	mustFail(t, ctx, pool,
		`INSERT INTO certificates (project_id, issued_at, not_after, identifiers, secret_ref)
		 VALUES ($1, now(), now() - interval '1 day', ARRAY['example.com'], 'secret://tls/1')`,
		"certificates_window_ordered", projectID)

	mustFail(t, ctx, pool,
		`INSERT INTO certificates (project_id, issued_at, not_after, identifiers, secret_ref)
		 VALUES ($1, now(), now() + interval '90 days', ARRAY['example.com'], '')`,
		"certificates_secret_ref_present", projectID)

	// An empty identifier set is not a certificate.
	mustFail(t, ctx, pool,
		`INSERT INTO certificates (project_id, issued_at, not_after, identifiers, secret_ref)
		 VALUES ($1, now(), now() + interval '90 days', ARRAY[]::text[], 'secret://tls/1')`,
		"certificates_identifiers_bounded", projectID)

	// A revoked certificate must record when.
	mustFail(t, ctx, pool,
		`INSERT INTO certificates (project_id, issued_at, not_after, identifiers, secret_ref, state)
		 VALUES ($1, now(), now() + interval '90 days', ARRAY['example.com'], 'secret://tls/1', 'revoked')`,
		"certificates_revoked_shape", projectID)
}

// Exactly one current certificate per hostname, which is what makes "which
// certificate is live for example.com?" a single-row question.
func TestOneCurrentCertificatePerHostname(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")
	siteID := insertSite(t, ctx, pool, projectID, serverID, "www")

	var domainID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO site_domains (site_id, hostname) VALUES ($1, 'example.com') RETURNING id`,
		siteID).Scan(&domainID); err != nil {
		t.Fatalf("insert site_domain: %v", err)
	}

	newCert := func(ref string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO certificates (project_id, issued_at, not_after, identifiers, secret_ref)
			 VALUES ($1, now(), now() + interval '90 days', ARRAY['example.com'], $2) RETURNING id`,
			projectID, ref).Scan(&id); err != nil {
			t.Fatalf("insert certificate %s: %v", ref, err)
		}
		return id
	}

	c1 := newCert("secret://tls/1")
	c2 := newCert("secret://tls/2")

	if _, err := pool.Exec(ctx,
		`INSERT INTO domain_certificates (site_domain_id, certificate_id, is_current)
		 VALUES ($1, $2, true)`, domainID, c1); err != nil {
		t.Fatalf("bind current certificate: %v", err)
	}

	// A second current binding for the same hostname is refused: this is the
	// constraint that keeps a renewal from leaving two live certificates.
	mustFail(t, ctx, pool,
		`INSERT INTO domain_certificates (site_domain_id, certificate_id, is_current)
		 VALUES ($1, $2, true)`,
		"domain_certificates_current_unique_idx", domainID, c2)

	// Deactivating the first, then binding the second, is the renewal path and
	// must succeed.
	if _, err := pool.Exec(ctx,
		`UPDATE domain_certificates SET is_current = false, deactivated_at = now()
		 WHERE site_domain_id = $1 AND certificate_id = $2`, domainID, c1); err != nil {
		t.Fatalf("deactivate previous certificate: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO domain_certificates (site_domain_id, certificate_id, is_current)
		 VALUES ($1, $2, true)`, domainID, c2); err != nil {
		t.Fatalf("bind renewed certificate: %v", err)
	}
}

// The is_current flag and deactivated_at must agree, so "is this binding live?"
// has one answer rather than two that can disagree.
func TestDomainCertificateCurrentShapeIsEnforced(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	serverID := insertServer(t, ctx, pool, "node-1")
	siteID := insertSite(t, ctx, pool, projectID, serverID, "www")

	var domainID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO site_domains (site_id, hostname) VALUES ($1, 'example.com') RETURNING id`,
		siteID).Scan(&domainID); err != nil {
		t.Fatalf("insert site_domain: %v", err)
	}

	var certID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO certificates (project_id, issued_at, not_after, identifiers, secret_ref)
		 VALUES ($1, now(), now() + interval '90 days', ARRAY['example.com'], 'secret://tls/1') RETURNING id`,
		projectID).Scan(&certID); err != nil {
		t.Fatalf("insert certificate: %v", err)
	}

	mustFail(t, ctx, pool,
		`INSERT INTO domain_certificates (site_domain_id, certificate_id, is_current, deactivated_at)
		 VALUES ($1, $2, true, now())`,
		"domain_certificates_current_shape", domainID, certID)
}

// One live membership per (project, user), while removed memberships are kept
// so the history of who had access survives.
func TestProjectMembershipIsUniqueAmongLiveOnly(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")
	userID := insertUser(t, ctx, pool, "member@example.test", false)

	var membershipID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO project_memberships (project_id, user_id) VALUES ($1, $2) RETURNING id`,
		projectID, userID).Scan(&membershipID); err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	mustFail(t, ctx, pool,
		`INSERT INTO project_memberships (project_id, user_id) VALUES ($1, $2)`,
		"project_memberships_live_unique_idx", projectID, userID)

	// Removed, then re-added: allowed, and the old row is retained.
	if _, err := pool.Exec(ctx,
		`UPDATE project_memberships SET removed_at = now() WHERE id = $1`, membershipID); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO project_memberships (project_id, user_id) VALUES ($1, $2)`,
		projectID, userID); err != nil {
		t.Fatalf("re-add membership: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM project_memberships WHERE project_id = $1 AND user_id = $2`,
		projectID, userID).Scan(&count); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if count != 2 {
		t.Errorf("membership rows = %d, want 2 (history retained)", count)
	}
}

// A quota of NULL means "inherit the platform default"; 0 means "none allowed".
// Those must not collapse, so a negative is refused while both NULL and 0 are
// accepted.
func TestQuotaDistinguishesUnsetFromZero(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	projectID := insertProject(t, ctx, pool, "acme")

	if _, err := pool.Exec(ctx, `INSERT INTO project_quotas (project_id) VALUES ($1)`, projectID); err != nil {
		t.Fatalf("insert quota with everything unset: %v", err)
	}

	mustFail(t, ctx, pool,
		`UPDATE project_quotas SET sites = -1 WHERE project_id = $1`,
		"project_quotas_sites_check", projectID)

	if _, err := pool.Exec(ctx,
		`UPDATE project_quotas SET sites = 0, disk_bytes = 0 WHERE project_id = $1`, projectID); err != nil {
		t.Fatalf("zero quota must be allowed and distinct from unset: %v", err)
	}

	// One quota row per project.
	mustFail(t, ctx, pool,
		`INSERT INTO project_quotas (project_id) VALUES ($1)`,
		"project_quotas_pkey", projectID)
}

// THE PERMISSION THAT HAD NO REACHABLE PATH. `logs.read` is server-scoped, so a
// customer holding a project-scoped grant cannot satisfy it. `site.logs.read`
// must exist, be project-scoped, and be granted to the roles that can already
// read a site — a permission inserted without grants would be dead on arrival,
// the same defect class as a column with a reader and no writer.
func TestSiteLogsPermissionIsProjectScopedAndGranted(t *testing.T) {
	pool := applyRealMigrations(t)
	ctx := context.Background()

	var scopeKind string
	var requiresStepUp bool
	err := pool.QueryRow(ctx,
		`SELECT scope_kind, requires_step_up FROM permissions WHERE key = 'site.logs.read'`).
		Scan(&scopeKind, &requiresStepUp)
	if err != nil {
		t.Fatalf("site.logs.read is missing: %v", err)
	}
	if scopeKind != "project" {
		t.Errorf("site.logs.read scope_kind = %q, want %q", scopeKind, "project")
	}
	if requiresStepUp {
		t.Errorf("site.logs.read requires step-up; reading an owned site's logs is not a privileged act")
	}

	// Every role that can read a site must be able to read its logs, or the
	// permission exists but is unreachable for the people who need it.
	var ungranted []string
	rows, err := pool.Query(ctx,
		`SELECT r.key
		   FROM roles r
		  WHERE EXISTS (SELECT 1 FROM role_permissions rp
		                 WHERE rp.role_id = r.id AND rp.permission_key = 'site.read')
		    AND NOT EXISTS (SELECT 1 FROM role_permissions rp
		                     WHERE rp.role_id = r.id AND rp.permission_key = 'site.logs.read')
		  ORDER BY r.key`)
	if err != nil {
		t.Fatalf("query ungranted roles: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatalf("scan role: %v", err)
		}
		ungranted = append(ungranted, key)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate roles: %v", err)
	}
	if len(ungranted) != 0 {
		t.Errorf("roles that can read a site but not its logs: %v", ungranted)
	}

	// The viewer role is defined as "strictly *.read", so it must hold it too.
	var viewerHas bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM role_permissions rp
		                  JOIN roles r ON r.id = rp.role_id
		                 WHERE r.key = 'viewer' AND rp.permission_key = 'site.logs.read')`).
		Scan(&viewerHas); err != nil {
		t.Fatalf("query viewer grant: %v", err)
	}
	if !viewerHas {
		t.Error("viewer role can read a site but not its logs")
	}
}
