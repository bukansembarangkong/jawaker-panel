//go:build integration

package certs

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestWorkerSweepMarksExpiringAndNotifies proves that the renewal worker
// detects certificates nearing expiration, transitions them to 'expiring',
// and publishes a 'cert.expiring' notification.
func TestWorkerSweepMarksExpiringAndNotifies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	now := f.clock.now()
	cert, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now.Add(-60 * 24 * time.Hour),
		NotAfter:      now.Add(10 * 24 * time.Hour), // expires in 10 days
		Identifiers:   []string{"soon.example.com"},
		PrivateKeyPEM: "KEY-SOON",
		ChainPEM:      "CERT-SOON",
	})
	if err != nil {
		t.Fatalf("record cert: %v", err)
	}

	w := NewWorker(WorkerConfig{
		Pool:   f.pool,
		Certs:  f.store,
		Window: 30 * 24 * time.Hour,
	})

	if err := w.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	updated, err := f.store.Get(ctx, cert.ID)
	if err != nil {
		t.Fatalf("Get updated cert: %v", err)
	}
	if updated.State != StateExpiring {
		t.Errorf("state = %q, want expiring", updated.State)
	}

	var count int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM notification_deliveries
		 WHERE dedup_key = $1`, "cert.expiring:"+cert.ID).Scan(&count); err != nil {
		t.Fatalf("query notifications: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one notification delivery for cert.expiring")
	}
}

// TestSafeRenewCandidateRetainsPreviousOnFailure proves the Gate 4 invariant:
// "previous valid certificate remains available during failed renewal".
// If candidate validation fails, the existing binding is completely untouched.
func TestSafeRenewCandidateRetainsPreviousOnFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	now := f.clock.now()

	// 1. Record and bind the original valid certificate
	certA, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now.Add(-60 * 24 * time.Hour),
		NotAfter:      now.Add(30 * 24 * time.Hour),
		Identifiers:   []string{"example.com"},
		PrivateKeyPEM: "KEY-A",
		ChainPEM:      "CERT-A",
	})
	if err != nil {
		t.Fatalf("record cert A: %v", err)
	}
	if err := f.store.Bind(ctx, f.domainID, certA.ID); err != nil {
		t.Fatalf("bind cert A: %v", err)
	}

	// 2. Record a candidate certificate
	certB, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now,
		NotAfter:      now.Add(90 * 24 * time.Hour),
		Identifiers:   []string{"example.com"},
		PrivateKeyPEM: "KEY-B",
		ChainPEM:      "CERT-B",
	})
	if err != nil {
		t.Fatalf("record cert B: %v", err)
	}

	w := NewWorker(WorkerConfig{
		Pool:  f.pool,
		Certs: f.store,
	})

	// 3. Attempt renewal with a failing validation function
	err = w.SafeRenewCandidate(ctx, f.domainID, certB.ID, func(c Certificate) error {
		return errors.New("simulated validation failure")
	})
	if err == nil {
		t.Fatal("expected validation failure, got nil")
	}

	// 4. Verify that Cert A is still the current bound certificate
	current, err := f.store.CurrentForDomain(ctx, f.domainID)
	if err != nil {
		t.Fatalf("CurrentForDomain: %v", err)
	}
	if current.ID != certA.ID {
		t.Errorf("current id = %q, want certA %q (previous cert must remain bound on failure)", current.ID, certA.ID)
	}

	// 5. Verify that a successful validation binds Cert B
	err = w.SafeRenewCandidate(ctx, f.domainID, certB.ID, func(c Certificate) error {
		return nil
	})
	if err != nil {
		t.Fatalf("successful renewal: %v", err)
	}

	currentB, err := f.store.CurrentForDomain(ctx, f.domainID)
	if err != nil {
		t.Fatalf("CurrentForDomain after success: %v", err)
	}
	if currentB.ID != certB.ID {
		t.Errorf("current id = %q, want certB %q", currentB.ID, certB.ID)
	}
}
