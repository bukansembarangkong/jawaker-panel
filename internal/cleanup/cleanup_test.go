package cleanup

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestCleaner_NilPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(nil, logger, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// RunOnce must not panic on nil pool
	c.RunOnce(ctx)

	n, err := PurgeExpiredPreviews(ctx, nil, time.Hour)
	if err != nil || n != 0 {
		t.Errorf("expected (0, nil), got (%d, %v)", n, err)
	}

	j, err := PruneOldJobs(ctx, nil, time.Hour)
	if err != nil || j != 0 {
		t.Errorf("expected (0, nil), got (%d, %v)", j, err)
	}
}
