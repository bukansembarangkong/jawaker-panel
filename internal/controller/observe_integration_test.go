//go:build integration

package controller

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
)

// csrfDo sends a CSRF-correct request for any method (PATCH/DELETE included).
func (h *harness) csrfDo(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	token, _ := h.csrf()
	return h.do(method, path, body, map[string]string{
		auth.HeaderCSRF: token,
		"Origin":        h.server.URL,
	})
}

func TestObserveRoutesRequireSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('obs-unauth', '127.0.0.1:9470', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}

	routes := []struct{ method, path string }{
		{"GET", "/api/v1/servers/" + serverID + "/metrics?metric=cpu_pct"},
		{"GET", "/api/v1/alert-rules"},
		{"GET", "/api/v1/incidents"},
		{"GET", "/api/v1/report-schedules"},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestObserveAlertRuleCRUD(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('obs-rule', '127.0.0.1:9471', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}

	// Invalid metric is rejected before anything is stored.
	bad := `{"server_id":"` + serverID + `","name":"bad","metric":"nope","comparator":"gt","threshold":1}`
	if resp := h.post(t, "/api/v1/alert-rules", bad); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST invalid metric = %d, want 400", resp.StatusCode)
	}

	body := `{"server_id":"` + serverID + `","name":"hot cpu","metric":"cpu_pct","comparator":"gt","threshold":90,"duration_seconds":120,"severity":"critical"}`
	resp := h.post(t, "/api/v1/alert-rules", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST alert-rules = %d, want 201", resp.StatusCode)
	}
	var created struct {
		Rule struct {
			ID         string  `json:"id"`
			Metric     string  `json:"metric"`
			Comparator string  `json:"comparator"`
			Threshold  float64 `json:"threshold"`
			Severity   string  `json:"severity"`
			Enabled    bool    `json:"enabled"`
		} `json:"rule"`
	}
	decodeBody(t, resp, &created)
	if created.Rule.ID == "" || created.Rule.Severity != "critical" || !created.Rule.Enabled {
		t.Errorf("created rule = %+v", created.Rule)
	}

	// PATCH updates the threshold and disables the rule.
	patch := `{"threshold":95,"enabled":false}`
	patchResp := h.csrfDo(t, http.MethodPatch, "/api/v1/alert-rules/"+created.Rule.ID, patch)
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH alert-rule = %d, want 200", patchResp.StatusCode)
	}
	var updated struct {
		Rule struct {
			Threshold float64 `json:"threshold"`
			Enabled   bool    `json:"enabled"`
		} `json:"rule"`
	}
	decodeBody(t, patchResp, &updated)
	if updated.Rule.Threshold != 95 || updated.Rule.Enabled {
		t.Errorf("updated rule = %+v", updated.Rule)
	}

	// Unknown id is a 404, not a panic or a 500.
	if r := h.csrfDo(t, http.MethodPatch, "/api/v1/alert-rules/00000000-0000-0000-0000-000000000000", patch); r.StatusCode != http.StatusNotFound {
		t.Errorf("PATCH unknown = %d, want 404", r.StatusCode)
	}

	// DELETE removes it; a second DELETE is a 404.
	del := h.csrfDo(t, http.MethodDelete, "/api/v1/alert-rules/"+created.Rule.ID, "")
	if del.StatusCode != http.StatusOK {
		t.Fatalf("DELETE alert-rule = %d, want 200", del.StatusCode)
	}
	del2 := h.csrfDo(t, http.MethodDelete, "/api/v1/alert-rules/"+created.Rule.ID, "")
	if del2.StatusCode != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", del2.StatusCode)
	}

	// Mutations are audited.
	var audited int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action IN ('monitoring.rule.create','monitoring.rule.update','monitoring.rule.delete')`,
	).Scan(&audited); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audited != 3 {
		t.Errorf("audit rows = %d, want 3 (create+update+delete)", audited)
	}
}

func TestObserveMetricsQuery(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('obs-metrics', '127.0.0.1:9472', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	now := time.Now().UTC()
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO metric_samples (server_id, metric, value, observed_at) VALUES ($1,'cpu_pct',42,$2),($1,'cpu_pct',57,$3)`,
		serverID, now.Add(-10*time.Minute), now.Add(-5*time.Minute),
	); err != nil {
		t.Fatalf("insert samples: %v", err)
	}

	base := "/api/v1/servers/" + serverID + "/metrics"

	// metric is required.
	if resp := h.do("GET", base, "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no metric = %d, want 400", resp.StatusCode)
	}
	// Unknown metric is rejected.
	if resp := h.do("GET", base+"?metric=nope", "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad metric = %d, want 400", resp.StatusCode)
	}
	// Malformed since is rejected.
	if resp := h.do("GET", base+"?metric=cpu_pct&since=yesterday", "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad since = %d, want 400", resp.StatusCode)
	}

	resp := h.do("GET", base+"?metric=cpu_pct", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET metrics = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Samples []struct {
			Value      float64   `json:"value"`
			ObservedAt time.Time `json:"observed_at"`
		} `json:"samples"`
	}
	decodeBody(t, resp, &out)
	if len(out.Samples) != 2 {
		t.Fatalf("samples = %d, want 2", len(out.Samples))
	}
	// Newest first.
	if out.Samples[0].Value != 57 {
		t.Errorf("first sample = %v, want 57 (newest)", out.Samples[0].Value)
	}

	// since= filters the window.
	since := now.Add(-7 * time.Minute).Format(time.RFC3339)
	filtered := h.do("GET", base+"?metric=cpu_pct&since="+since, "", nil)
	var out2 struct {
		Samples []map[string]any `json:"samples"`
	}
	decodeBody(t, filtered, &out2)
	if len(out2.Samples) != 1 {
		t.Errorf("filtered samples = %d, want 1", len(out2.Samples))
	}
}

func TestObserveIncidentsListAndResolve(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var serverID, ruleID, incidentID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('obs-inc', '127.0.0.1:9473', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO alert_rules (server_id, name, metric, comparator, threshold)
		 VALUES ($1,'disk full','disk_pct','gt',90) RETURNING id`, serverID,
	).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO alert_incidents (rule_id, server_id, dedup_key)
		 VALUES ($1,$2,$3) RETURNING id`, ruleID, serverID, "rule:"+ruleID,
	).Scan(&incidentID); err != nil {
		t.Fatalf("insert incident: %v", err)
	}

	// state filter is validated.
	if resp := h.do("GET", "/api/v1/incidents?state=bogus", "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad state = %d, want 400", resp.StatusCode)
	}

	resp := h.do("GET", "/api/v1/incidents?state=open", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET incidents = %d, want 200", resp.StatusCode)
	}
	var list struct {
		Incidents []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"incidents"`
		Total int `json:"total"`
	}
	decodeBody(t, resp, &list)
	if list.Total != 1 || list.Incidents[0].ID != incidentID {
		t.Errorf("incidents = %+v", list)
	}

	// Resolve via the API.
	res := h.post(t, "/api/v1/incidents/"+incidentID+"/resolve", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("resolve = %d, want 200", res.StatusCode)
	}
	// Resolving twice is a conflict, not a silent success.
	res2 := h.post(t, "/api/v1/incidents/"+incidentID+"/resolve", "")
	if res2.StatusCode != http.StatusConflict {
		t.Errorf("second resolve = %d, want 409", res2.StatusCode)
	}

	// Unknown incident id: store uses a single UPDATE (cannot distinguish
	// not-found from already-resolved), so ErrState → 409 is correct here.
	res3 := h.post(t, "/api/v1/incidents/00000000-0000-0000-0000-000000000000/resolve", "")
	if res3.StatusCode != http.StatusConflict {
		t.Errorf("resolve unknown = %d, want 409 (store cannot distinguish not-found from already-resolved)", res3.StatusCode)
	}
}

func TestObserveReportSchedules(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	// Bad cadence is rejected.
	if resp := h.post(t, "/api/v1/report-schedules", `{"name":"x","cadence":"hourly"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad cadence = %d, want 400", resp.StatusCode)
	}

	resp := h.post(t, "/api/v1/report-schedules", `{"name":"Weekly Digest","cadence":"weekly"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST report-schedules = %d, want 201", resp.StatusCode)
	}
	var created struct {
		Schedule struct {
			ID      string `json:"id"`
			Cadence string `json:"cadence"`
			Enabled bool   `json:"enabled"`
		} `json:"schedule"`
	}
	decodeBody(t, resp, &created)
	if created.Schedule.ID == "" || created.Schedule.Cadence != "weekly" || !created.Schedule.Enabled {
		t.Errorf("created schedule = %+v", created.Schedule)
	}

	list := h.do("GET", "/api/v1/report-schedules", "", nil)
	var out struct {
		Schedules []map[string]any `json:"schedules"`
		Total     int              `json:"total"`
	}
	decodeBody(t, list, &out)
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}

	del := h.csrfDo(t, http.MethodDelete, "/api/v1/report-schedules/"+created.Schedule.ID, "")
	if del.StatusCode != http.StatusOK {
		t.Fatalf("DELETE schedule = %d, want 200", del.StatusCode)
	}
	del2 := h.csrfDo(t, http.MethodDelete, "/api/v1/report-schedules/"+created.Schedule.ID, "")
	if del2.StatusCode != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", del2.StatusCode)
	}

	var audited int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action IN ('monitoring.schedule.create','monitoring.schedule.delete')`,
	).Scan(&audited); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audited != 2 {
		t.Errorf("audit rows = %d, want 2", audited)
	}
}
