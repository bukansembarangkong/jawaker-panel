package backups

import (
	"testing"
	"time"
)

func TestNextRun(t *testing.T) {
	// 2026-01-15 is a Thursday.
	base := time.Date(2026, 1, 15, 10, 30, 45, 0, time.UTC)

	cases := []struct {
		expr string
		want time.Time
	}{
		{"0 * * * *", time.Date(2026, 1, 15, 11, 0, 0, 0, time.UTC)},
		{"45 10 * * *", time.Date(2026, 1, 15, 10, 45, 0, 0, time.UTC)},
		{"0 0 * * *", time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC)},
		{"0 0 1 * *", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"0 0 * * 1", time.Date(2026, 1, 19, 0, 0, 0, 0, time.UTC)}, // next Monday
		{"*/15 * * * *", time.Date(2026, 1, 15, 10, 45, 0, 0, time.UTC)},
		{"0 9-17 * * 1-5", time.Date(2026, 1, 15, 11, 0, 0, 0, time.UTC)},
		// 10:00 and 10:30 today are both behind the base time; next fire is tomorrow 10:00.
		{"0,30 10 * * *", time.Date(2026, 1, 16, 10, 0, 0, 0, time.UTC)},
	}

	for _, c := range cases {
		got, err := NextRun(c.expr, base)
		if err != nil {
			t.Errorf("NextRun(%q): %v", c.expr, err)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("NextRun(%q) = %s, want %s", c.expr, got.Format(time.RFC3339), c.want.Format(time.RFC3339))
		}
	}
}

func TestNextRunRejects(t *testing.T) {
	bad := []string{"", "* * *", "60 * * * *", "* 24 * * *", "a * * * *", "*/0 * * * *"}
	from := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	for _, expr := range bad {
		if _, err := NextRun(expr, from); err == nil {
			t.Errorf("NextRun(%q) accepted, want error", expr)
		}
	}
}

func TestNextRunIsStrictlyAfter(t *testing.T) {
	// An exact match on the current minute must advance to the next one.
	from := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	got, err := NextRun("0 * * * *", from)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 1, 15, 11, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %s, want %s", got, want)
	}
}
