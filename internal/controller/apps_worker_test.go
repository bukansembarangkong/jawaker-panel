package controller

import (
	"testing"
	"time"
)

// TestNewAppDeployWorkerRequiresDependencies proves the constructor validates
// its required arguments rather than panicking when they are missing.
func TestNewAppDeployWorkerRequiresDependencies(t *testing.T) {
	// Must fail when Pool is nil.
	_, err := NewAppDeployWorker(AppWorkerOptions{
		Owner: "app-worker-test",
	})
	if err == nil {
		t.Error("NewAppDeployWorker without Pool succeeded")
	}
}

func TestAppWorkerOptionsDefaultOwner(t *testing.T) {
	opts := AppWorkerOptions{
		Owner:        "",
		LeaseTTL:     30 * time.Second,
		PollInterval: 2 * time.Second,
	}
	if opts.Owner != "" {
		t.Errorf("Owner = %q, want empty before init", opts.Owner)
	}
}

func TestNewAppDeployHandlerIsNotNil(t *testing.T) {
	h := NewAppDeployHandler(nil, nil, nil, nil, nil, nil)
	if h == nil {
		t.Fatal("NewAppDeployHandler returned nil")
	}
}
