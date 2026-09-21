//go:build integration

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestAppRoutesRequireSession proves app endpoints refuse unauthenticated requests.
func TestAppRoutesRequireSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	// Insert a project so the path resolves to a real id.
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('unauth-app-test', 'Unauth App Test', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/projects/" + projectID + "/apps", ""},
		{"POST", "/api/v1/projects/" + projectID + "/apps", `{"slug":"x","name":"X","runtime_type":"node","git_repo_url":"https://example.com/r.git","server_id":"00000000-0000-0000-0000-000000000001"}`},
		{"GET", "/api/v1/projects/" + projectID + "/apps/00000000-0000-0000-0000-000000000001", ""},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, tc.body, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestAppCreationAndRetrieval proves the owner can create an app and get it back.
func TestAppCreationAndRetrieval(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('app-test-host', '127.0.0.1:9444', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('app-project', 'App Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"slug":            "api",
		"name":            "API Service",
		"runtime_type":    "node",
		"git_repo_url":    "https://github.com/example/api.git",
		"git_ref_default": "main",
		"start_program":   "node",
		"start_args":      []string{"dist/index.js"},
		"server_id":       serverID,
	})
	resp := h.post(t, "/api/v1/projects/"+projectID+"/apps", string(body))
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("POST apps = %d, want 201; body = %v", resp.StatusCode, errBody)
	}

	var created struct {
		App struct {
			ID          string `json:"id"`
			Slug        string `json:"slug"`
			RuntimeType string `json:"runtime_type"`
			ProjectID   string `json:"project_id"`
		} `json:"app"`
	}
	decodeBody(t, resp, &created)
	if created.App.Slug != "api" {
		t.Errorf("slug = %q, want api", created.App.Slug)
	}
	if created.App.RuntimeType != "node" {
		t.Errorf("runtime_type = %q, want node", created.App.RuntimeType)
	}
	if created.App.ProjectID != projectID {
		t.Errorf("project_id = %q, want %q", created.App.ProjectID, projectID)
	}

	// Retrieve via GET.
	getResp := h.do("GET", "/api/v1/projects/"+projectID+"/apps/"+created.App.ID, "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET app = %d, want 200", getResp.StatusCode)
	}
	var got struct {
		App struct {
			ID string `json:"id"`
		} `json:"app"`
	}
	decodeBody(t, getResp, &got)
	if got.App.ID != created.App.ID {
		t.Errorf("GET app id = %q, want %q", got.App.ID, created.App.ID)
	}
}

// TestAppDeployEnqueuesJobAndReturnsAccepted proves the deploy endpoint creates
// a deployment record and enqueues an app.deploy job, returning 202.
func TestAppDeployEnqueuesJobAndReturnsAccepted(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('deploy-host', '127.0.0.1:9445', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('deploy-project', 'Deploy Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	// Create app.
	appBody, _ := json.Marshal(map[string]any{
		"slug":          "deploy-api",
		"name":          "Deploy API",
		"runtime_type":  "node",
		"git_repo_url":  "https://github.com/example/deploy-api.git",
		"start_program": "node",
		"start_args":    []string{"index.js"},
		"server_id":     serverID,
	})
	createResp := h.post(t, "/api/v1/projects/"+projectID+"/apps", string(appBody))
	if createResp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, createResp, &errBody)
		t.Fatalf("POST apps = %d; body = %v", createResp.StatusCode, errBody)
	}
	var createdApp struct {
		App struct {
			ID string `json:"id"`
		} `json:"app"`
	}
	decodeBody(t, createResp, &createdApp)
	appID := createdApp.App.ID

	// Trigger deploy.
	h.elevate(t)
	deployResp := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/deploy",
		`{"commit_sha":"abc1234","git_ref":"main"}`)
	if deployResp.StatusCode != http.StatusAccepted {
		var errBody map[string]any
		decodeBody(t, deployResp, &errBody)
		t.Fatalf("POST deploy = %d, want 202; body = %v", deployResp.StatusCode, errBody)
	}

	var deployBody struct {
		DeploymentID string `json:"deployment_id"`
		Job          struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"job"`
	}
	decodeBody(t, deployResp, &deployBody)
	if deployBody.DeploymentID == "" {
		t.Error("deployment_id is empty")
	}
	if deployBody.Job.ID == "" {
		t.Error("job.id is empty")
	}
	if deployBody.Job.State != "queued" {
		t.Errorf("job.state = %q, want queued", deployBody.Job.State)
	}

	// Verify the deployment record in the database.
	var depState string
	if err := h.pool.QueryRow(ctx,
		`SELECT state FROM app_deployments WHERE id = $1`, deployBody.DeploymentID,
	).Scan(&depState); err != nil {
		t.Fatalf("query deployment: %v", err)
	}
	if depState != "queued" {
		t.Errorf("deployment state = %q, want queued", depState)
	}

	// Verify the job is claimable.
	var jobType string
	if err := h.pool.QueryRow(ctx,
		`SELECT type FROM jobs WHERE id = $1`, deployBody.Job.ID,
	).Scan(&jobType); err != nil {
		t.Fatalf("query job: %v", err)
	}
	if jobType != JobTypeAppDeploy {
		t.Errorf("job.type = %q, want %q", jobType, JobTypeAppDeploy)
	}
}

// TestAppDeployConflictsWhenActiveDeployExists proves Gate 4: a second deploy
// attempt while one is already queued or running returns 409 Conflict.
func TestAppDeployConflictsWhenActiveDeployExists(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('conflict-host', '127.0.0.1:9446', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('conflict-project', 'Conflict Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	// Create app.
	appBody, _ := json.Marshal(map[string]any{
		"slug":          "conflict-app",
		"name":          "Conflict App",
		"runtime_type":  "node",
		"git_repo_url":  "https://github.com/example/conflict-app.git",
		"start_program": "node",
		"start_args":    []string{"index.js"},
		"server_id":     serverID,
	})
	createResp := h.post(t, "/api/v1/projects/"+projectID+"/apps", string(appBody))
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST apps = %d", createResp.StatusCode)
	}
	var createdApp struct {
		App struct {
			ID string `json:"id"`
		} `json:"app"`
	}
	decodeBody(t, createResp, &createdApp)
	appID := createdApp.App.ID

	// First deploy succeeds.
	h.elevate(t)
	first := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/deploy",
		`{"commit_sha":"def5678"}`)
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first POST deploy = %d, want 202", first.StatusCode)
	}

	// Second deploy must conflict while first is queued.
	h.elevate(t)
	second := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/deploy",
		`{"commit_sha":"def5678"}`)
	if second.StatusCode != http.StatusConflict {
		t.Errorf("second POST deploy = %d, want 409", second.StatusCode)
	}

	_ = ctx
}

// TestAppDeployRefusesMissingCommitSHA proves the deploy endpoint requires an
// exact commit SHA: the node fetches by SHA, so a ref-only request would need a
// resolution step that does not exist. Refusing at the boundary is the honest
// answer (PRD §10: exact-commit redeploy).
func TestAppDeployRefusesMissingCommitSHA(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('sha-host', '127.0.0.1:9448', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('sha-project', 'SHA Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	appBody, _ := json.Marshal(map[string]any{
		"slug":          "sha-app",
		"name":          "SHA App",
		"runtime_type":  "node",
		"git_repo_url":  "https://github.com/example/sha-app.git",
		"start_program": "node",
		"start_args":    []string{"index.js"},
		"server_id":     serverID,
	})
	createResp := h.post(t, "/api/v1/projects/"+projectID+"/apps", string(appBody))
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST apps = %d", createResp.StatusCode)
	}
	var createdApp struct {
		App struct {
			ID string `json:"id"`
		} `json:"app"`
	}
	decodeBody(t, createResp, &createdApp)
	appID := createdApp.App.ID

	// No commit_sha at all.
	h.elevate(t)
	resp := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/deploy", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("deploy without commit_sha = %d, want 400", resp.StatusCode)
	}

	// A ref is NOT a SHA.
	h.elevate(t)
	resp2 := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/deploy", `{"commit_sha":"main"}`)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("deploy with ref as commit_sha = %d, want 400", resp2.StatusCode)
	}

	// Uppercase hex is not lowercase.
	h.elevate(t)
	resp3 := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/deploy", `{"commit_sha":"ABC1234"}`)
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("deploy with uppercase sha = %d, want 400", resp3.StatusCode)
	}

	// No deployment rows were created by any refused request.
	var count int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM app_deployments WHERE app_id = $1`, appID,
	).Scan(&count); err != nil {
		t.Fatalf("count deployments: %v", err)
	}
	if count != 0 {
		t.Errorf("refused deploys created %d deployment rows, want 0", count)
	}
}

// TestAppEnvVarMaskingNeverReturnsSecretRef proves that secret_ref env vars
// never expose the plaintext value to the client.
func TestAppEnvVarMaskingNeverReturnsSecretRef(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('env-test-host', '127.0.0.1:9447', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('env-project', 'Env Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	// Create app.
	appBody, _ := json.Marshal(map[string]any{
		"slug":          "env-app",
		"name":          "Env App",
		"runtime_type":  "node",
		"git_repo_url":  "https://github.com/example/env-app.git",
		"start_program": "node",
		"start_args":    []string{"index.js"},
		"server_id":     serverID,
	})
	createResp := h.post(t, "/api/v1/projects/"+projectID+"/apps", string(appBody))
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST apps = %d", createResp.StatusCode)
	}
	var createdApp struct {
		App struct {
			ID string `json:"id"`
		} `json:"app"`
	}
	decodeBody(t, createResp, &createdApp)
	appID := createdApp.App.ID

	// Set a literal env var.
	h.elevate(t)
	setResp := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/env", `{"name":"NODE_ENV","value_source":"literal","value":"production"}`)
	if setResp.StatusCode != http.StatusOK {
		var errBody map[string]any
		decodeBody(t, setResp, &errBody)
		t.Fatalf("POST env = %d; body = %v", setResp.StatusCode, errBody)
	}

	// Set a secret_ref env var.
	h.elevate(t)
	setSecretResp := h.post(t, "/api/v1/projects/"+projectID+"/apps/"+appID+"/env", `{"name":"DB_PASS","value_source":"secret_ref","value":"secret://app/db-pass"}`)
	if setSecretResp.StatusCode != http.StatusOK {
		var errBody map[string]any
		decodeBody(t, setSecretResp, &errBody)
		t.Fatalf("POST env secret = %d; body = %v", setSecretResp.StatusCode, errBody)
	}

	// List env vars: literal must have value, secret_ref must not have literal value exposed.
	listResp := h.do("GET", "/api/v1/projects/"+projectID+"/apps/"+appID+"/env", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET env = %d, want 200", listResp.StatusCode)
	}

	var envBody struct {
		EnvVars []struct {
			Name        string  `json:"name"`
			ValueSource string  `json:"value_source"`
			Value       *string `json:"value,omitempty"`
			SecretRef   any     `json:"secret_ref,omitempty"`
		} `json:"env_vars"`
	}
	decodeBody(t, listResp, &envBody)
	for _, ev := range envBody.EnvVars {
		if ev.Name == "NODE_ENV" {
			if ev.Value == nil || *ev.Value != "production" {
				t.Errorf("NODE_ENV value = %v, want production", ev.Value)
			}
		}
		if ev.Name == "DB_PASS" {
			if ev.Value != nil {
				t.Errorf("DB_PASS secret_ref row must not expose a literal value; got %q", *ev.Value)
			}
		}
	}
	_ = ctx
}
