package updates

import (
	"testing"
	"time"
)

func TestReleaseValidation(t *testing.T) {
	r := Release{
		Channel:     "stable",
		Version:     "1.2.3",
		Tag:         "v1.2.3",
		ArtifactURL: "https://github.com/bukansembarangkong/jawaker-panel/releases/download/v1.2.3/jawaker-panel_linux_amd64.tar.gz",
		ChecksumURL: "https://github.com/bukansembarangkong/jawaker-panel/releases/download/v1.2.3/checksums.txt",
		PublishedAt: time.Now(),
	}
	if r.Channel == "" {
		t.Error("channel must not be empty")
	}
	if r.Version == "" {
		t.Error("version must not be empty")
	}
	if r.ArtifactURL == "" {
		t.Error("artifact_url must not be empty")
	}
}

func TestJobStateTransitions(t *testing.T) {
	validStates := []string{"pending", "preflight", "downloading", "verifying",
		"applying", "done", "failed", "rolled_back"}
	seen := map[string]bool{}
	for _, s := range validStates {
		seen[s] = true
	}
	for _, s := range validStates {
		if !seen[s] {
			t.Errorf("state %q missing from valid set", s)
		}
	}
}

func TestCanaryStates(t *testing.T) {
	validStates := []string{"pending", "applying", "done", "failed", "paused"}
	if len(validStates) != 5 {
		t.Errorf("expected 5 canary states, got %d", len(validStates))
	}
}

func TestModuleStates(t *testing.T) {
	validStates := []string{"idle", "updating", "done", "failed"}
	if len(validStates) != 4 {
		t.Errorf("expected 4 module states, got %d", len(validStates))
	}
}

func TestSnapshotStates(t *testing.T) {
	validStates := []string{"pending", "running", "ready", "failed", "restored"}
	if len(validStates) != 5 {
		t.Errorf("expected 5 snapshot states, got %d", len(validStates))
	}
}
