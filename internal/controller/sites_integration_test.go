//go:build integration

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestSiteRoutesRequireSession proves site endpoints refuse unauthenticated
// requests before anything else, consistent with every other protected route in
// this controller.
func TestSiteRoutesRequireSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	// Insert a project so the path resolves to a real id, not a bad uuid error.
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('unauth-test', 'Unauth Test', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/projects/" + projectID + "/sites", ""},
		{"POST", "/api/v1/projects/" + projectID + "/sites", `{"slug":"x","name":"X","mode":"static","server_id":"00000000-0000-0000-0000-000000000001"}`},
		{"GET", "/api/v1/projects/" + projectID + "/sites/00000000-0000-0000-0000-000000000001", ""},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, tc.body, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestSiteCreationAndRetrieval proves the owner can create a site and get it back.
func TestSiteCreationAndRetrieval(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	// Insert server (FK required by sites)
	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('test-host', '127.0.0.1:9443', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	// Insert project
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('my-project', 'My Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"slug":      "www",
		"name":      "Main Site",
		"mode":      "static",
		"server_id": serverID,
	})
	resp := h.post(t, "/api/v1/projects/"+projectID+"/sites", string(body))
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("POST sites = %d, want 201; body = %v", resp.StatusCode, errBody)
	}

	var created struct {
		Site struct {
			ID        string `json:"id"`
			Slug      string `json:"slug"`
			Mode      string `json:"mode"`
			ProjectID string `json:"project_id"`
		} `json:"site"`
	}
	decodeBody(t, resp, &created)
	if created.Site.Slug != "www" {
		t.Errorf("slug = %q, want www", created.Site.Slug)
	}
	if created.Site.Mode != "static" {
		t.Errorf("mode = %q, want static", created.Site.Mode)
	}
	if created.Site.ProjectID != projectID {
		t.Errorf("project_id = %q, want %q", created.Site.ProjectID, projectID)
	}

	// Retrieve via GET
	getResp := h.do("GET", "/api/v1/projects/"+projectID+"/sites/"+created.Site.ID, "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET site = %d, want 200", getResp.StatusCode)
	}
}

// TestSiteListFiltersToProject proves the list endpoint returns only sites
// belonging to the named project and never leaks from another project.
func TestSiteListFiltersToProject(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	// Insert shared server + two projects
	var serverID, projectA, projectB string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('shared-host', '127.0.0.1:9443', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('proj-a', 'Project A', 'active') RETURNING id`,
	).Scan(&projectA); err != nil {
		t.Fatalf("insert project A: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('proj-b', 'Project B', 'active') RETURNING id`,
	).Scan(&projectB); err != nil {
		t.Fatalf("insert project B: %v", err)
	}

	// Create 2 sites in A, 1 in B (different slug per project to avoid constraint)
	for _, slug := range []string{"site-a1", "site-a2"} {
		body, _ := json.Marshal(map[string]any{"slug": slug, "name": slug, "mode": "static", "server_id": serverID})
		if resp := h.post(t, "/api/v1/projects/"+projectA+"/sites", string(body)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("create site-A %s = %d", slug, resp.StatusCode)
		}
	}
	body, _ := json.Marshal(map[string]any{"slug": "site-b1", "name": "site-b1", "mode": "static", "server_id": serverID})
	if resp := h.post(t, "/api/v1/projects/"+projectB+"/sites", string(body)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create site-B = %d", resp.StatusCode)
	}

	// List project A -> exactly 2
	listResp := h.do("GET", "/api/v1/projects/"+projectA+"/sites", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list A = %d, want 200", listResp.StatusCode)
	}
	var listBody struct {
		Sites []map[string]any `json:"sites"`
		Total int              `json:"total"`
	}
	decodeBody(t, listResp, &listBody)
	if listBody.Total != 2 || len(listBody.Sites) != 2 {
		t.Errorf("list A total=%d len=%d, want 2", listBody.Total, len(listBody.Sites))
	}
	for _, s := range listBody.Sites {
		if s["project_id"] != projectA {
			t.Errorf("list A leaked site from project %s", s["project_id"])
		}
	}
}

// TestSiteCrossProjectAccess401 proves that a user with site.read on project A
// cannot access sites in project B, and the response is 403 (no grant on B),
// not 200 or a leaked row.
// CRITICAL: once the handler loads the site via GetInProject, a site from project B
// returns ErrNotFound -> 404, so the id doesn't disclose cross-project existence.
func TestSiteGetCrossProjectReturns404(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectA, projectB string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('cross-host', '127.0.0.1:9443', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('cross-a', 'Cross A', 'active') RETURNING id`,
	).Scan(&projectA); err != nil {
		t.Fatalf("insert A: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('cross-b', 'Cross B', 'active') RETURNING id`,
	).Scan(&projectB); err != nil {
		t.Fatalf("insert B: %v", err)
	}

	// Create a site in project B
	body, _ := json.Marshal(map[string]any{"slug": "site-b", "name": "Site B", "mode": "static", "server_id": serverID})
	bResp := h.post(t, "/api/v1/projects/"+projectB+"/sites", string(body))
	if bResp.StatusCode != http.StatusCreated {
		t.Fatalf("create site in B = %d", bResp.StatusCode)
	}
	var bCreated struct {
		Site struct {
			ID string `json:"id"`
		} `json:"site"`
	}
	decodeBody(t, bResp, &bCreated)
	siteBID := bCreated.Site.ID

	// Access site-B's id using project-A's path.
	// User is the owner, so they PASS the ProjectScope(projectA) RBAC check.
	// But GetInProject(projectA, siteBID) returns ErrNotFound -> 404.
	getResp := h.do("GET", "/api/v1/projects/"+projectA+"/sites/"+siteBID, "", nil)
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("cross-project GET status = %d, want 404 (must not expose cross-project site ids)", getResp.StatusCode)
	}
}

// TestSiteDeleteRequiresStepUp proves that site.delete is step-up gated and
// answered 403 step_up_required while unelevated, and 200 once elevated.
func TestSiteDeleteRequiresStepUp(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('del-host', '127.0.0.1:9443', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('del-project', 'Del Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"slug": "to-delete", "name": "To Delete", "mode": "static", "server_id": serverID})
	cResp := h.post(t, "/api/v1/projects/"+projectID+"/sites", string(body))
	if cResp.StatusCode != http.StatusCreated {
		t.Fatalf("create site = %d", cResp.StatusCode)
	}
	var created struct {
		Site struct {
			ID string `json:"id"`
		} `json:"site"`
	}
	decodeBody(t, cResp, &created)
	siteID := created.Site.ID

	// DELETE without elevation -> 403 step_up_required
	delResp := h.post(t, "/api/v1/projects/"+projectID+"/sites/"+siteID+"/THIS_IS_DELETE", "")
	// The route is DELETE not POST, use h.do
	delUnelevated := h.do("DELETE", "/api/v1/projects/"+projectID+"/sites/"+siteID, "", nil)
	if delUnelevated.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE unelevated = %d, want 403", delUnelevated.StatusCode)
	}
	var errBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decodeBody(t, delUnelevated, &errBody)
	if errBody.Error.Code != "step_up_required" {
		t.Errorf("error code = %q, want step_up_required", errBody.Error.Code)
	}
	_ = delResp

	// Elevate then DELETE -> 200 pending_delete
	h.elevate(t)
	delElevated := h.do("DELETE", "/api/v1/projects/"+projectID+"/sites/"+siteID, "", nil)
	if delElevated.StatusCode != http.StatusOK {
		var errB map[string]any
		decodeBody(t, delElevated, &errB)
		t.Fatalf("DELETE elevated = %d, want 200; body = %v", delElevated.StatusCode, errB)
	}
	var delBody struct {
		Status string `json:"status"`
	}
	decodeBody(t, delElevated, &delBody)
	if delBody.Status != "pending_delete" {
		t.Errorf("status = %q, want pending_delete", delBody.Status)
	}
}

// TestSiteApplyEnqueuesJobAndCreatesRevision proves that POST .../apply
// creates a revision in the database and returns a job reference in the response.
// The actual execution (node activation) is deferred to a job worker per the
// async pattern (API.md §7, PRD.md §38.1).
func TestSiteApplyEnqueuesJobAndCreatesRevision(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('apply-host', '127.0.0.1:9443', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('apply-project', 'Apply Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	siteBody, _ := json.Marshal(map[string]any{"slug": "apply-site", "name": "Apply Site", "mode": "static", "server_id": serverID})
	cResp := h.post(t, "/api/v1/projects/"+projectID+"/sites", string(siteBody))
	if cResp.StatusCode != http.StatusCreated {
		t.Fatalf("create site = %d", cResp.StatusCode)
	}
	var created struct {
		Site struct {
			ID string `json:"id"`
		} `json:"site"`
	}
	decodeBody(t, cResp, &created)
	siteID := created.Site.ID

	// Apply a candidate config (no real node, so validator pre-flight is skipped;
	// the handler guards nil dispatcher with ServiceUnavailable for validate/apply
	// node calls, but continues to record the revision and enqueue the job).
	applyBody, _ := json.Marshal(map[string]any{
		"config":   "server { listen 80; server_name example.com; }",
		"filename": "apply-site.conf",
	})
	applyResp := h.post(t, "/api/v1/projects/"+projectID+"/sites/"+siteID+"/apply", string(applyBody))
	// When the dispatcher is nil the pre-flight is skipped, so we expect 202.
	if applyResp.StatusCode != http.StatusAccepted {
		var errB map[string]any
		decodeBody(t, applyResp, &errB)
		t.Fatalf("POST apply = %d, want 202; body = %v", applyResp.StatusCode, errB)
	}

	var applyBody2 struct {
		RevisionID string `json:"revision_id"`
		Job        struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"job"`
	}
	decodeBody(t, applyResp, &applyBody2)
	if applyBody2.RevisionID == "" {
		t.Error("revision_id is empty in apply response")
	}
	if applyBody2.Job.ID == "" {
		t.Error("job.id is empty in apply response")
	}
	if applyBody2.Job.State == "" {
		t.Error("job.state is empty in apply response")
	}

	// Verify the revision exists in the database
	var revCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM revisions WHERE id = $1 AND resource_type = 'site' AND resource_id = $2`,
		applyBody2.RevisionID, siteID).Scan(&revCount); err != nil {
		t.Fatalf("count revisions: %v", err)
	}
	if revCount != 1 {
		t.Errorf("revision count = %d, want 1", revCount)
	}

	// Verify the job exists in the database
	var jobCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM jobs WHERE id = $1 AND type = 'site.apply'`,
		applyBody2.Job.ID).Scan(&jobCount); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobCount != 1 {
		t.Errorf("job count = %d, want 1", jobCount)
	}
}
