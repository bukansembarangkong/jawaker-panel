package doctor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// --- the panic gate ----------------------------------------------------------

// THE property that makes doctor usable on a broken installation: one check
// dying must not destroy the report about every OTHER check. An operator runs
// doctor precisely when something is already wrong.
func TestRunSurvivesAPanickingCheck(t *testing.T) {
	report := Run(context.Background(), "controller", "test", fixedClock,
		Diagnose("before", func(context.Context) Check { return ok("before", "fine", nil) }),
		Diagnose("explodes", func(context.Context) Check { panic("a subsystem is corrupt") }),
		Diagnose("after", func(context.Context) Check { return ok("after", "also fine", nil) }),
	)

	if len(report.Checks) != 3 {
		t.Fatalf("checks = %d, want 3: a panicking check must not stop the ones after it", len(report.Checks))
	}
	panicCheck := report.Checks[1]
	// The NAME must survive the panic: that is the whole reason a check's name
	// lives in a Diagnostic rather than in its return value, which a panic never
	// produces.
	if panicCheck.Name != "explodes" {
		t.Errorf("panicking check name = %q, want %q", panicCheck.Name, "explodes")
	}
	if panicCheck.Status != StatusFail {
		t.Errorf("panicking check status = %q, want %q", panicCheck.Status, StatusFail)
	}
	if !strings.Contains(panicCheck.Detail, "a subsystem is corrupt") {
		t.Errorf("detail = %q, want it to name the panic value", panicCheck.Detail)
	}
	if report.Checks[0].Status != StatusOK || report.Checks[2].Status != StatusOK {
		t.Error("a check adjacent to the panicking one did not complete")
	}
	if report.Healthy() {
		t.Error("a report containing a panic was called healthy")
	}
}

// A panic's stack must be clipped: a full goroutine dump is mostly runtime
// internals and would bury the frames that identify the panic site.
func TestPanicEvidenceKeepsOnlyTheRelevantFrames(t *testing.T) {
	report := Run(context.Background(), "controller", "test", fixedClock,
		Diagnose("explodes", func(context.Context) Check { panic("boom") }),
	)
	stack, _ := report.Checks[0].Evidence["stack"].(string)
	if stack == "" {
		t.Fatal("no stack was recorded with the panic")
	}
	if lines := strings.Count(stack, "\n") + 1; lines > 12 {
		t.Errorf("stack has %d lines, want at most 12", lines)
	}
}

// A check that forgets its own name must still be identifiable, so an unnamed row
// never appears in a report an operator has to grep.
func TestUnnamedCheckIsGivenItsDeclaredName(t *testing.T) {
	report := Run(context.Background(), "controller", "test", fixedClock,
		Diagnose("named-by-declaration", func(context.Context) Check {
			return Check{Status: StatusOK, Detail: "no name of my own"}
		}),
	)
	if got := report.Checks[0].Name; got != "named-by-declaration" {
		t.Errorf("name = %q, want the declared name to be applied", got)
	}
}

// --- the status vocabulary ----------------------------------------------------

func TestCountsAndHealthyFollowFromStatuses(t *testing.T) {
	report := Run(context.Background(), "controller", "test", fixedClock,
		Diagnose("a", func(context.Context) Check { return ok("a", "", nil) }),
		Diagnose("b", func(context.Context) Check { return warn("b", "", nil) }),
		Diagnose("c", func(context.Context) Check { return skip("c", "") }),
	)
	if !report.Healthy() {
		t.Fatal("a report with no failed check was called unhealthy")
	}
	c := report.Count()
	if c.OK != 1 || c.Warn != 1 || c.Skip != 1 || c.Fail != 0 {
		t.Errorf("counts = %+v, want one of each of ok/warn/skip", c)
	}

	// A warning and a skip must NOT make a component unhealthy: a warning is by
	// definition survivable, and a skip means "not measured" rather than "broken".
	// Treating a skip as a failure would make doctor report a problem on every
	// non-Linux host for the disk check alone.
	noFailures := Run(context.Background(), "controller", "test", fixedClock,
		Diagnose("w", func(context.Context) Check { return warn("w", "", nil) }),
		Diagnose("s", func(context.Context) Check { return skip("s", "") }),
	)
	if !noFailures.Healthy() {
		t.Error("warnings or skips made the component unhealthy")
	}

	// And a real failure must flip it, or the gate means nothing.
	withFailure := Run(context.Background(), "controller", "test", fixedClock,
		Diagnose("f", func(context.Context) Check { return fail("f", "broken", nil) }),
	)
	if withFailure.Healthy() {
		t.Error("a failed check did not make the component unhealthy")
	}
}

// --- rendering ----------------------------------------------------------------

// The text output must carry the check names and the failure, and the status word
// must be a WORD rather than a symbol: reports get pasted into issue trackers
// that render color codes unpredictably.
func TestTextOutputNamesChecksAndFailures(t *testing.T) {
	report := Run(context.Background(), "controller", "v9", fixedClock,
		Diagnose("database", func(context.Context) Check { return ok("database", "connected", nil) }),
		Diagnose("migrations", func(context.Context) Check { return fail("migrations", "two pending", nil) }),
	)
	text := report.Text()
	for _, want := range []string{"controller", "v9", "database", "migrations", "two pending", "FAIL", "1 FAILED"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output is missing %q\n%s", want, text)
		}
	}
	// Counts that are zero are omitted rather than printed as ", 0 warning".
	if strings.Contains(text, "0 warning") || strings.Contains(text, "0 skipped") {
		t.Errorf("text output pads the summary with zero counts\n%s", text)
	}
}

// JSON output must round-trip, because it is the machine-readable form a
// monitoring system consumes and a typo in a field name would only surface there.
func TestJSONRoundTrips(t *testing.T) {
	report := Run(context.Background(), "node-agent", "v1", fixedClock,
		Diagnose("disk", func(context.Context) Check {
			return warn("disk", "low space", map[string]any{"free_bytes": int64(1024)})
		}),
	)
	raw, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Component != "node-agent" || len(back.Checks) != 1 {
		t.Fatalf("round-tripped report = %+v", back)
	}
	if back.Checks[0].Status != StatusWarn {
		t.Errorf("status = %q, want %q", back.Checks[0].Status, StatusWarn)
	}
	// Evidence must survive, or the "concrete evidence, not a score" requirement
	// is only met in the text renderer.
	if back.Checks[0].Evidence["free_bytes"] != float64(1024) {
		t.Errorf("evidence = %+v, want free_bytes preserved", back.Checks[0].Evidence)
	}
}

// --- formatting ---------------------------------------------------------------

// Binary units, because every filesystem tool an operator compares against
// reports them; a report that disagrees with df is a report that gets ignored.
func TestHumanBytesUsesBinaryUnits(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB"},
	} {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRemainingStatesExpiryClearly(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{-time.Hour, "expired"},
		{0, "expired"},
		{90 * time.Minute, "1 hours"},
		{30 * time.Hour, "30 hours"},
		{72 * time.Hour, "3 days"},
	} {
		if got := remaining(tc.in); got != tc.want {
			t.Errorf("remaining(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// fixedClock is a deterministic clock so a report's timestamp and every expiry
// comparison in these tests are reproducible.
func fixedClock() time.Time {
	return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
}
