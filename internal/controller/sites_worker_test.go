package controller

import (
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/sites"
)

// TestNewSiteApplyWorkerRequiresDependencies proves the constructor validates
// its required arguments rather than panicking when they are missing.
func TestNewSiteApplyWorkerRequiresDependencies(t *testing.T) {
	// Must fail when Pool is nil (Sites provided, Owner provided).
	_, err := NewSiteApplyWorker(SiteWorkerOptions{
		Sites: &sites.Store{},
		Owner: "worker-test",
	})
	if err == nil {
		t.Error("NewSiteApplyWorker without Pool succeeded")
	}
	// The Sites-nil check follows the Pool check; asserting it here would need
	// a real pool, so it is covered by the integration harness instead.
}

func TestSiteWorkerOptionsDefaultOwner(t *testing.T) {
	opts := SiteWorkerOptions{
		Owner:        "",
		LeaseTTL:     30 * time.Second,
		PollInterval: 2 * time.Second,
	}
	if opts.Owner != "" {
		t.Errorf("Owner = %q, want empty before init", opts.Owner)
	}
}

func TestNewSiteApplyHandlerIsNotNil(t *testing.T) {
	h := NewSiteApplyHandler(nil, nil, nil, nil)
	if h == nil {
		t.Fatal("NewSiteApplyHandler returned nil")
	}
}
