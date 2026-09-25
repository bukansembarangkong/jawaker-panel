package revisions

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

type mockSyncer struct {
	sha string
	err error
}

func (m *mockSyncer) SyncRevision(ctx context.Context, rev Revision) (string, error) {
	return m.sha, m.err
}

func TestGitSyncWorker_NilPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := NewGitSyncWorker(nil, &mockSyncer{sha: "abc1234"}, logger, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Should not panic or error with nil pool
	if err := w.DrainOnce(ctx, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
