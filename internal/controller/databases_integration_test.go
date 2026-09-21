//go:build integration

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestDatabaseRoutesRequireSession proves database endpoints refuse unauthenticated requests.
func TestDatabaseRoutesRequireSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('unauth-db-test', 'Unauth DB Test', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/projects/" + projectID + "/databases", ""},
		{"POST", "/api/v1/projects/" + projectID + "/databases", `{"slug":"testdb","name":"Test","engine":"postgresql","engine_version":"17","db_name":"testdb","server_id":"00000000-0000-0000-0000-000000000001"}`},
		{"GET", "/api/v1/projects/" + projectID + "/databases/00000000-0000-0000-0000-000000000001", ""},
		{"GET", "/api/v1/projects/" + projectID + "/databases/00000000-0000-0000-0000-000000000001/users", ""},
		{"GET", "/api/v1/projects/" + projectID + "/databases/00000000-0000-0000-0000-000000000001/connection-string", ""},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, tc.body, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestDatabaseCreationAndRetrieval proves the owner can create a database and retrieve it.
func TestDatabaseCreationAndRetrieval(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('db-host', '127.0.0.1:9445', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('db-project', 'DB Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"slug":           "main_pg",
		"name":           "Main PostgreSQL",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "main_prod",
		"server_id":      serverID,
	})
	resp := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(body))
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("POST databases = %d, want 201; body = %v", resp.StatusCode, errBody)
	}

	var created struct {
		Database struct {
			ID        string `json:"id"`
			Slug      string `json:"slug"`
			Engine    string `json:"engine"`
			DBName    string `json:"db_name"`
			State     string `json:"state"`
			ProjectID string `json:"project_id"`
		} `json:"database"`
	}
	decodeBody(t, resp, &created)
	if created.Database.Slug != "main_pg" {
		t.Errorf("slug = %q, want main_pg", created.Database.Slug)
	}
	if created.Database.Engine != "postgresql" {
		t.Errorf("engine = %q, want postgresql", created.Database.Engine)
	}
	if created.Database.DBName != "main_prod" {
		t.Errorf("db_name = %q, want main_prod", created.Database.DBName)
	}
	if created.Database.State != "active" {
		t.Errorf("state = %q, want active", created.Database.State)
	}

	// GET single.
	getResp := h.do("GET", "/api/v1/projects/"+projectID+"/databases/"+created.Database.ID, "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET database = %d, want 200", getResp.StatusCode)
	}

	// LIST in project.
	listResp := h.do("GET", "/api/v1/projects/"+projectID+"/databases", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET databases list = %d, want 200", listResp.StatusCode)
	}
	var listResult struct {
		Databases []map[string]any `json:"databases"`
		Total     int              `json:"total"`
	}
	decodeBody(t, listResp, &listResult)
	if listResult.Total != 1 {
		t.Errorf("total = %d, want 1", listResult.Total)
	}
}

// TestDatabaseSlugConflict proves duplicate slugs in the same project return 409.
func TestDatabaseSlugConflict(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('db-host-conflict', '127.0.0.1:9446', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('db-proj-conflict', 'Conflict Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"slug":           "app_db",
		"name":           "First DB",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "app_db_1",
		"server_id":      serverID,
	})
	resp1 := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(body))
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first POST = %d, want 201", resp1.StatusCode)
	}

	// Second database with SAME slug but different db_name: must 409.
	body2, _ := json.Marshal(map[string]any{
		"slug":           "app_db",
		"name":           "Second DB",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "app_db_2",
		"server_id":      serverID,
	})
	resp2 := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(body2))
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate slug POST = %d, want 409", resp2.StatusCode)
	}
}

// TestDatabaseCrossProjectIsolation proves Gate 1: accessing a database belonging
// to Project A from Project B returns 404 Not Found, never 403 Forbidden.
// This prevents enumeration oracles across tenant boundaries.
func TestDatabaseCrossProjectIsolation(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('iso-host', '127.0.0.1:9447', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	var projA, projB string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('proj-a', 'Project A', 'active') RETURNING id`,
	).Scan(&projA); err != nil {
		t.Fatalf("insert projA: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('proj-b', 'Project B', 'active') RETURNING id`,
	).Scan(&projB); err != nil {
		t.Fatalf("insert projB: %v", err)
	}

	// Create database in Project A.
	body, _ := json.Marshal(map[string]any{
		"slug":           "isolated_db",
		"name":           "Isolated DB",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "isolated_db",
		"server_id":      serverID,
	})
	createResp := h.post(t, "/api/v1/projects/"+projA+"/databases", string(body))
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create in projA = %d, want 201", createResp.StatusCode)
	}
	var created struct {
		Database struct {
			ID string `json:"id"`
		} `json:"database"`
	}
	decodeBody(t, createResp, &created)
	dbID := created.Database.ID

	// Gate 1: Attempt to access projA's database using projB's route.
	// MUST return 404 (Not Found), NOT 403 (Forbidden), to avoid disclosing existence.
	leakResp := h.do("GET", "/api/v1/projects/"+projB+"/databases/"+dbID, "", nil)
	if leakResp.StatusCode != http.StatusNotFound {
		t.Errorf("cross-project GET = %d, want 404 (anti-enumeration Gate 1)", leakResp.StatusCode)
	}

	// Also verify users route returns 404 when database is accessed through wrong project.
	userLeakResp := h.do("GET", "/api/v1/projects/"+projB+"/databases/"+dbID+"/users", "", nil)
	if userLeakResp.StatusCode != http.StatusNotFound {
		t.Errorf("cross-project GET /users = %d, want 404 (anti-enumeration Gate 1)", userLeakResp.StatusCode)
	}

	// Also verify connection-string route returns 404.
	csLeakResp := h.do("GET", "/api/v1/projects/"+projB+"/databases/"+dbID+"/connection-string", "", nil)
	if csLeakResp.StatusCode != http.StatusNotFound {
		t.Errorf("cross-project GET /connection-string = %d, want 404 (anti-enumeration Gate 1)", csLeakResp.StatusCode)
	}
}

// TestDatabaseUserPasswordNeverReturnedInAPI proves Gate 3: creating a user
// generates and seals a password via secret.Store; the plaintext password is
// NEVER returned in the create response or subsequent list responses.
func TestDatabaseUserPasswordNeverReturnedInAPI(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('sec-host', '127.0.0.1:9448', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('sec-proj', 'Security Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	// Create DB first.
	dbBody, _ := json.Marshal(map[string]any{
		"slug":           "secrets_test_db",
		"name":           "Secrets Test DB",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "secrets_test_db",
		"server_id":      serverID,
	})
	dbResp := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(dbBody))
	if dbResp.StatusCode != http.StatusCreated {
		t.Fatalf("create db = %d, want 201", dbResp.StatusCode)
	}
	var createdDB struct {
		Database struct {
			ID string `json:"id"`
		} `json:"database"`
	}
	decodeBody(t, dbResp, &createdDB)
	dbID := createdDB.Database.ID

	// Create database user.
	userBody, _ := json.Marshal(map[string]any{
		"username":   "app_writer",
		"privileges": []string{"SELECT", "INSERT", "UPDATE"},
	})
	userResp := h.post(t, "/api/v1/projects/"+projectID+"/databases/"+dbID+"/users", string(userBody))
	if userResp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, userResp, &errBody)
		t.Fatalf("create user = %d, want 201; err = %v", userResp.StatusCode, errBody)
	}

	// Read raw body bytes to verify NO password field is present anywhere.
	var rawUserResp map[string]any
	decodeBody(t, userResp, &rawUserResp)
	userObj, ok := rawUserResp["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'user' object in response: %v", rawUserResp)
	}

	// Gate 3: Assert password is NOT returned in create response.
	if _, hasPass := userObj["password"]; hasPass {
		t.Errorf("Gate 3 violation: 'password' field returned in create user response: %v", userObj)
	}
	if _, hasPlain := userObj["plain_password"]; hasPlain {
		t.Errorf("Gate 3 violation: 'plain_password' field returned in create user response: %v", userObj)
	}

	// Secret ref must be present and formatted as secret://.
	secretRef, _ := userObj["secret_ref"].(string)
	if !strings.HasPrefix(secretRef, "secret://") {
		t.Errorf("secret_ref = %q, want secret:// prefix", secretRef)
	}

	// List users and verify password is NOT present there either.
	listResp := h.do("GET", "/api/v1/projects/"+projectID+"/databases/"+dbID+"/users", "", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /users = %d, want 200", listResp.StatusCode)
	}
	var listResult struct {
		Users []map[string]any `json:"users"`
	}
	decodeBody(t, listResp, &listResult)
	if len(listResult.Users) != 1 {
		t.Fatalf("users count = %d, want 1", len(listResult.Users))
	}
	listedUser := listResult.Users[0]
	if _, hasPass := listedUser["password"]; hasPass {
		t.Errorf("Gate 3 violation: 'password' returned in list users response: %v", listedUser)
	}
}

// TestRotatePasswordReturns204NoContent proves Gate 3 password rotation:
// step-up is required; response is 204 No Content; new password is never in body.
func TestRotatePasswordReturns204NoContent(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('rot-host', '127.0.0.1:9449', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('rot-proj', 'Rotation Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	// Create DB + User.
	dbBody, _ := json.Marshal(map[string]any{
		"slug":           "rot_db",
		"name":           "Rot DB",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "rot_db",
		"server_id":      serverID,
	})
	dbResp := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(dbBody))
	var createdDB struct {
		Database struct {
			ID string `json:"id"`
		} `json:"database"`
	}
	decodeBody(t, dbResp, &createdDB)
	dbID := createdDB.Database.ID

	userBody, _ := json.Marshal(map[string]any{"username": "rot_user"})
	h.post(t, "/api/v1/projects/"+projectID+"/databases/"+dbID+"/users", string(userBody))

	// Rotate WITHOUT elevation must return 403 step_up_required.
	rotatePath := "/api/v1/projects/" + projectID + "/databases/" + dbID + "/users/rot_user/rotate-password"
	unelevatedResp := h.post(t, rotatePath, "")
	if unelevatedResp.StatusCode != http.StatusForbidden {
		t.Errorf("unelevated rotate = %d, want 403 step_up_required", unelevatedResp.StatusCode)
	}

	// Elevate session.
	h.elevate(t)

	// Elevated rotate MUST return 204 No Content (Gate 3).
	elevatedResp := h.post(t, rotatePath, "")
	if elevatedResp.StatusCode != http.StatusNoContent {
		t.Fatalf("elevated rotate = %d, want 204 No Content (Gate 3)", elevatedResp.StatusCode)
	}
	if elevatedResp.ContentLength > 0 {
		t.Errorf("204 response has ContentLength = %d, want 0", elevatedResp.ContentLength)
	}
}

// TestConnectionStringOpensSecret proves connection string endpoint opens the
// sealed secret in memory and formats a valid connection URI without leaking to logs.
func TestConnectionStringOpensSecret(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('cs-host', '127.0.0.1:9450', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('cs-proj', 'CS Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	dbBody, _ := json.Marshal(map[string]any{
		"slug":           "cs_db",
		"name":           "CS DB",
		"engine":         "postgresql",
		"engine_version": "17",
		"db_name":        "cs_db_prod",
		"server_id":      serverID,
	})
	dbResp := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(dbBody))
	var createdDB struct {
		Database struct {
			ID string `json:"id"`
		} `json:"database"`
	}
	decodeBody(t, dbResp, &createdDB)
	dbID := createdDB.Database.ID

	// Create user.
	userBody, _ := json.Marshal(map[string]any{"username": "app_client"})
	h.post(t, "/api/v1/projects/"+projectID+"/databases/"+dbID+"/users", string(userBody))

	// Get connection string.
	csResp := h.do("GET", "/api/v1/projects/"+projectID+"/databases/"+dbID+"/connection-string", "", nil)
	if csResp.StatusCode != http.StatusOK {
		var errBody map[string]any
		decodeBody(t, csResp, &errBody)
		t.Fatalf("GET connection-string = %d, want 200; err = %v", csResp.StatusCode, errBody)
	}

	var result struct {
		ConnectionString string `json:"connection_string"`
		Username         string `json:"username"`
		Engine           string `json:"engine"`
		DBName           string `json:"db_name"`
	}
	decodeBody(t, csResp, &result)

	if !strings.HasPrefix(result.ConnectionString, "postgresql://app_client:") {
		t.Errorf("connection_string = %q, want prefix postgresql://app_client:", result.ConnectionString)
	}
	if !strings.Contains(result.ConnectionString, "/cs_db_prod?sslmode=disable") {
		t.Errorf("connection_string = %q, want db name cs_db_prod", result.ConnectionString)
	}
	if result.Username != "app_client" {
		t.Errorf("username = %q, want app_client", result.Username)
	}
}

// TestDatabaseDeleteRequiresStepUp proves deleting a database requires step-up elevation.
func TestDatabaseDeleteRequiresStepUp(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('del-host', '127.0.0.1:9451', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('del-proj', 'Del Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	dbBody, _ := json.Marshal(map[string]any{
		"slug":           "del_db",
		"name":           "Del DB",
		"engine":         "mariadb",
		"engine_version": "11.4",
		"db_name":        "del_db",
		"server_id":      serverID,
	})
	dbResp := h.post(t, "/api/v1/projects/"+projectID+"/databases", string(dbBody))
	var createdDB struct {
		Database struct {
			ID string `json:"id"`
		} `json:"database"`
	}
	decodeBody(t, dbResp, &createdDB)
	dbID := createdDB.Database.ID

	// DELETE without elevation: 403 step_up_required.
	delResp := h.do("DELETE", "/api/v1/projects/"+projectID+"/databases/"+dbID, "", nil)
	if delResp.StatusCode != http.StatusForbidden {
		t.Errorf("unelevated DELETE = %d, want 403", delResp.StatusCode)
	}

	// Elevate session.
	h.elevate(t)

	// DELETE with elevation: 200 OK.
	elevDelResp := h.do("DELETE", "/api/v1/projects/"+projectID+"/databases/"+dbID, "", nil)
	if elevDelResp.StatusCode != http.StatusOK {
		t.Fatalf("elevated DELETE = %d, want 200", elevDelResp.StatusCode)
	}
	var delResult struct {
		Status string `json:"status"`
	}
	decodeBody(t, elevDelResp, &delResult)
	if delResult.Status != "pending_delete" {
		t.Errorf("status = %q, want pending_delete", delResult.Status)
	}
}
