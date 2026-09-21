//go:build integration

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestProjectRoutesRequireSession proves project endpoints refuse unauthenticated requests.
func TestProjectRoutesRequireSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	// Insert a project row so the path is well-formed.
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('unauth-proj', 'Unauth Proj', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/projects"},
		{"GET", "/api/v1/projects/" + projectID},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestProjectListAndCreate proves that an authenticated owner can list and create projects.
func TestProjectListAndCreate(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	csrfToken, _ := h.csrf()

	// POST /api/v1/projects — create a project.
	body, _ := json.Marshal(map[string]any{
		"slug": "integration-project",
		"name": "Integration Project",
	})
	resp := h.csrfPost("/api/v1/projects", string(body), csrfToken)
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("POST /api/v1/projects = %d, want 201; body = %v", resp.StatusCode, errBody)
	}

	var created struct {
		Project struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"project"`
	}
	decodeBody(t, resp, &created)
	if created.Project.Slug != "integration-project" {
		t.Errorf("slug = %q, want integration-project", created.Project.Slug)
	}
	if created.Project.ID == "" {
		t.Error("expected non-empty project id")
	}

	// GET /api/v1/projects — list contains the new project.
	listResp := h.do("GET", "/api/v1/projects", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/projects = %d, want 200", listResp.StatusCode)
	}
	var listBody struct {
		Projects []struct {
			Slug string `json:"slug"`
		} `json:"projects"`
		Total int `json:"total"`
	}
	decodeBody(t, listResp, &listBody)
	if listBody.Total == 0 {
		t.Error("expected at least one project in list")
	}
	found := false
	for _, p := range listBody.Projects {
		if p.Slug == "integration-project" {
			found = true
		}
	}
	if !found {
		t.Error("created project not found in list")
	}
}

// TestProjectGetReturns404ForUnknown proves that an unknown project id returns 404.
func TestProjectGetReturns404ForUnknown(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	resp := h.do("GET", "/api/v1/projects/00000000-0000-0000-0000-000000000099", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET unknown project = %d, want 404", resp.StatusCode)
	}
}

// TestJobRouteRequiresSession proves the job route refuses unauthenticated requests.
func TestJobRouteRequiresSession(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.doRaw("GET", "/api/v1/jobs/00000000-0000-0000-0000-000000000099", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/jobs/... unauthenticated = %d, want 401", resp.StatusCode)
	}
}

// TestJobGetReturns404ForUnknown proves that an unknown job id returns 404, not 500.
func TestJobGetReturns404ForUnknown(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)

	resp := h.do("GET", "/api/v1/jobs/00000000-0000-0000-0000-000000000099", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET unknown job = %d, want 404", resp.StatusCode)
	}
}
