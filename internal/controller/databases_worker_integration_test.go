//go:build integration

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/databases"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// mockDBDispatcher implements databaseDispatcher for integration tests.
type mockDBDispatcher struct {
	restoreCalled bool
	metricsCalled bool
	restoreErr    error
	metricsErr    error
	metricsResult nodewire.DatabaseMetricsResult
}

func (m *mockDBDispatcher) ManageDatabase(_ context.Context, _, _ string, _ nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error) {
	return nodewire.DatabaseManageResult{OK: true}, nil
}

func (m *mockDBDispatcher) DumpDatabase(_ context.Context, _, _ string, _ nodewire.DatabaseDumpInput) (nodewire.DatabaseDumpResult, error) {
	return nodewire.DatabaseDumpResult{DumpPath: "/var/lib/jawaker/db-dumps/test.dump", SizeBytes: 1024, SHA256: "fake-sha"}, nil
}

func (m *mockDBDispatcher) RestoreDatabase(_ context.Context, _, _ string, _ nodewire.DatabaseRestoreInput) (nodewire.DatabaseRestoreResult, error) {
	m.restoreCalled = true
	if m.restoreErr != nil {
		return nodewire.DatabaseRestoreResult{}, m.restoreErr
	}
	return nodewire.DatabaseRestoreResult{OK: true}, nil
}

func (m *mockDBDispatcher) GetDatabaseMetrics(_ context.Context, _, _ string, _ nodewire.DatabaseMetricsInput) (nodewire.DatabaseMetricsResult, error) {
	m.metricsCalled = true
	if m.metricsErr != nil {
		return nodewire.DatabaseMetricsResult{}, m.metricsErr
	}
	return m.metricsResult, nil
}

// TestDatabaseRestoreRecoverability proves Gate 2:
// A database.restore job calls the node restore op, then executes a verification
// step via database.metrics that confirms the restored database can accept queries.
// The job marks itself completed only after the recoverability check succeeds.
func TestDatabaseRestoreRecoverability(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	var serverID, projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ('gate2-host', '127.0.0.1:9452', 'active') RETURNING id`,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('gate2-proj', 'Gate 2 Project', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	dbStore := databases.NewStore(h.pool, time.Now)
	db, err := dbStore.CreateDatabase(ctx, databases.CreateDatabaseParams{
		ProjectID:     projectID,
		ServerID:      serverID,
		Slug:          "gate2_db",
		Name:          "Gate 2 Recoverability Test DB",
		Engine:        databases.EnginePostgreSQL,
		EngineVersion: "17",
		DBName:        "gate2_db",
	})
	if err != nil {
		t.Fatalf("create db: %v", err)
	}

	// Mock node dispatcher that returns success on restore and 1 active connection on metrics.
	mockDisp := &mockDBDispatcher{
		metricsResult: nodewire.DatabaseMetricsResult{
			Connections: 1,
			ObservedAt:  time.Now().UTC(),
		},
	}

	// Enqueue the database.restore job.
	job, jErr := jobs.Enqueue(ctx, h.pool, jobs.Requested{
		Type:             JobTypeDatabaseRestore,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   "restore:gate2-test",
		IdempotencyScope: "database.restore:" + db.ID,
		Payload: map[string]any{
			"database_id": db.ID,
			"engine":      db.Engine,
			"db_name":     db.DBName,
			"dump_path":   "/var/lib/jawaker/db-dumps/test.dump",
		},
		Steps: []jobs.StepPlan{
			{Name: "restore"},
			{Name: "verify"},
		},
		LockKeys: []string{"database:" + db.ID},
	})
	if jErr != nil {
		t.Fatalf("enqueue restore job: %v", jErr)
	}

	// Construct worker with test seam.
	worker, wErr := NewDatabaseWorker(DatabaseWorkerOptions{
		Pool:               h.pool,
		Databases:          dbStore,
		dispatcherOverride: mockDisp,
		LeaseTTL:           30 * time.Second,
		PollInterval:       10 * time.Millisecond,
	})
	if wErr != nil {
		t.Fatalf("new database worker: %v", wErr)
	}

	// Run worker with a short timeout context to process the job.
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	runErrChan := make(chan error, 1)
	go func() {
		runErrChan <- worker.Run(runCtx)
	}()

	// Poll until the job completes or the run times out.
	deadline := time.Now().Add(3 * time.Second)
	var finalState string
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		var state string
		if err := h.pool.QueryRow(ctx, `SELECT state FROM jobs WHERE id = $1`, job.ID).Scan(&state); err == nil {
			if state == "succeeded" || state == "failed" {
				finalState = state
				break
			}
		}
	}
	cancel() // Stop the worker loop.
	<-runErrChan

	// Gate 2 assertions:
	if finalState != "succeeded" {
		t.Fatalf("job final state = %q, want succeeded (Gate 2)", finalState)
	}
	if !mockDisp.restoreCalled {
		t.Error("restore was not called on the dispatcher (Gate 2)")
	}
	if !mockDisp.metricsCalled {
		t.Error("metrics recoverability verification was not called on the dispatcher (Gate 2)")
	}

	// Verify both steps completed in job_steps.
	rows, queryErr := h.pool.Query(ctx,
		`SELECT name, state, output FROM job_steps WHERE job_id = $1 ORDER BY step_index`, job.ID)
	if queryErr != nil {
		t.Fatalf("query job_steps: %v", queryErr)
	}
	defer rows.Close()
	stepsByName := map[string]struct{ state, output string }{}
	for rows.Next() {
		var name, state string
		var output []byte
		if sErr := rows.Scan(&name, &state, &output); sErr != nil {
			t.Fatalf("scan step: %v", sErr)
		}
		stepsByName[name] = struct{ state, output string }{state, string(output)}
	}
	if s, ok := stepsByName["restore"]; !ok || s.state != "succeeded" {
		t.Errorf("restore step state = %q, want succeeded (Gate 2)", stepsByName["restore"].state)
	}
	if s, ok := stepsByName["verify"]; !ok || s.state != "succeeded" {
		t.Errorf("verify step state = %q, want succeeded (Gate 2)", stepsByName["verify"].state)
	}
	if verify := stepsByName["verify"]; !strings.Contains(verify.output, `"verified"`) || strings.Contains(verify.output, `"verified": false`) {
		t.Errorf("verify step output does not show verified (Gate 2), got: %s", verify.output)
	}
}
