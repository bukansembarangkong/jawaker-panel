//go:build integration

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestBackupRoutesRequireSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('unauth-bk-test', 'Unauth BK Test', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	routes := []struct{ method, path string }{
		{"GET", "/api/v1/projects/" + projectID + "/backup-plans"},
		{"GET", "/api/v1/projects/" + projectID + "/backup-runs"},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestBackupPlanCreationAndRetrieval(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('bk-host', '127.0.0.1:9460', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('bk-project', 'BK Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"server_id":        serverID,
		"name":             "Daily Files",
		"slug":             "daily_files",
		"scope_type":       "project",
		"destination_type": "local",
		"retention_count":  5,
		"retention_days":   14,
	})
	resp := h.post(t, "/api/v1/projects/"+projectID+"/backup-plans", string(body))
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("POST backup-plans = %d, want 201; body = %v", resp.StatusCode, errBody)
	}

	var created struct {
		Plan struct {
			ID        string `json:"id"`
			Slug      string `json:"slug"`
			State     string `json:"state"`
			ProjectID string `json:"project_id"`
		} `json:"plan"`
	}
	decodeBody(t, resp, &created)
	if created.Plan.Slug != "daily_files" {
		t.Errorf("slug = %q, want daily_files", created.Plan.Slug)
	}
	if created.Plan.State != "active" {
		t.Errorf("state = %q, want active", created.Plan.State)
	}

	getResp := h.do("GET", "/api/v1/projects/"+projectID+"/backup-plans/"+created.Plan.ID, "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET backup-plan = %d, want 200", getResp.StatusCode)
	}

	listResp := h.do("GET", "/api/v1/projects/"+projectID+"/backup-plans", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET backup-plans = %d, want 200", listResp.StatusCode)
	}
	var listResult struct {
		Plans []map[string]any `json:"plans"`
		Total int              `json:"total"`
	}
	decodeBody(t, listResp, &listResult)
	if listResult.Total != 1 {
		t.Errorf("total = %d, want 1", listResult.Total)
	}
}

func TestBackupPlanSlugConflict(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('bk-host2', '127.0.0.1:9461', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('bk-proj2', 'BK Proj 2', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"server_id":        serverID,
		"name":             "Plan A",
		"slug":             "plan_a",
		"scope_type":       "project",
		"destination_type": "local",
	})
	first := h.post(t, "/api/v1/projects/"+projectID+"/backup-plans", string(body))
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first create = %d, want 201", first.StatusCode)
	}
	second := h.post(t, "/api/v1/projects/"+projectID+"/backup-plans", string(body))
	if second.StatusCode != http.StatusConflict {
		t.Errorf("duplicate slug = %d, want 409", second.StatusCode)
	}
}

func TestBackupPlanCrossProjectIsolation(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projA, projB string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('bk-host3', '127.0.0.1:9462', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('bk-a', 'BK A', 'active') RETURNING id`,
	).Scan(&projA); err != nil {
		t.Fatalf("insert proj A: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('bk-b', 'BK B', 'active') RETURNING id`,
	).Scan(&projB); err != nil {
		t.Fatalf("insert proj B: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"server_id":        serverID,
		"name":             "Only A",
		"slug":             "only_a",
		"scope_type":       "project",
		"destination_type": "local",
	})
	resp := h.post(t, "/api/v1/projects/"+projA+"/backup-plans", string(body))
	var created struct {
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
	}
	decodeBody(t, resp, &created)

	// Reading A's plan through B's project returns 404 — cross-project reads
	// are indistinguishable from missing rows.
	cross := h.do("GET", "/api/v1/projects/"+projB+"/backup-plans/"+created.Plan.ID, "", nil)
	if cross.StatusCode != http.StatusNotFound {
		t.Errorf("cross-project GET = %d, want 404", cross.StatusCode)
	}
}

func TestBackupPlanDeleteRequiresStepUp(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('bk-host4', '127.0.0.1:9463', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('bk-del', 'BK Del', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"server_id":        serverID,
		"name":             "To Delete",
		"slug":             "to_delete",
		"scope_type":       "project",
		"destination_type": "local",
	})
	resp := h.post(t, "/api/v1/projects/"+projectID+"/backup-plans", string(body))
	var created struct {
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
	}
	decodeBody(t, resp, &created)

	// DELETE without elevation: 403 step_up_required.
	delResp := h.do("DELETE", "/api/v1/projects/"+projectID+"/backup-plans/"+created.Plan.ID, "", nil)
	if delResp.StatusCode != http.StatusForbidden {
		t.Errorf("unelevated DELETE = %d, want 403", delResp.StatusCode)
	}

	h.elevate(t)

	elevResp := h.do("DELETE", "/api/v1/projects/"+projectID+"/backup-plans/"+created.Plan.ID, "", nil)
	if elevResp.StatusCode != http.StatusOK {
		t.Fatalf("elevated DELETE = %d, want 200", elevResp.StatusCode)
	}
	var result struct {
		Status string `json:"status"`
	}
	decodeBody(t, elevResp, &result)
	if result.Status != "pending_delete" {
		t.Errorf("status = %q, want pending_delete", result.Status)
	}
}
