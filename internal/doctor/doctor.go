// Package doctor implements the `doctor` diagnostic command for both JAWAKER
// binaries.
//
// # What a diagnostic report is allowed to be
//
// SECURITY.md §20 forbids reducing security posture to a single score, so this
// package has no score type and no aggregate health verdict. Every check returns
// its own status and its own CONCRETE EVIDENCE — a certificate's remaining
// lifetime, a migration count, the name of a missing secret reference. An
// operator reading the output learns which specific thing is wrong, not that the
// installation is "72% healthy".
//
// # What a diagnostic must never do
//
// A doctor command runs against an installation that is probably already broken.
// Two rules follow from that:
//
//   - It is READ-ONLY. Nothing here creates a certificate authority, applies a
//     migration, repairs a permission, or binds a port it keeps. A diagnostic
//     that changes state turns "find out what is wrong" into "make a second
//     thing wrong", and it cannot be run twice with the same result.
//   - It NEVER CRASHES. A check that panics is reported as a failed check naming
//     the panic value, so a broken installation still produces a report about
//     everything else that was checked. Run enforces this with a recover, and
//     that behavior is asserted by a test rather than assumed.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"
)

// Status is a check's verdict. There are four rather than two, because "this
// check could not run" is a different fact from "this check ran and found a
// problem", and collapsing them would make an unreachable database look like a
// corrupt one.
type Status string

const (
	// StatusOK means the check ran and found nothing actionable.
	StatusOK Status = "ok"
	// StatusWarn means the check ran and found something worth attention that
	// does not stop the component from working. A certificate expiring in three
	// weeks is a warning; one that expired yesterday is a failure.
	StatusWarn Status = "warn"
	// StatusFail means the check ran and found a fault.
	StatusFail Status = "fail"
	// StatusSkip means the check COULD NOT RUN, typically because something it
	// depends on is unavailable. The reason is always in Detail: a skip without
	// a reason is indistinguishable from a bug.
	StatusSkip Status = "skip"
)

// Check is one diagnostic result.
type Check struct {
	// Name is a stable, lowercase, hyphenated identifier. Stable because an
	// operator may grep a report, and because a monitoring system that keys on
	// the name must not break when wording changes.
	Name string `json:"name"`
	// Status is the verdict.
	Status Status `json:"status"`
	// Detail is one human sentence stating what was found. It is written to be
	// read on its own, without the rest of the report.
	Detail string `json:"detail"`
	// Evidence carries the machine-readable facts behind Detail: counts,
	// timestamps, fingerprints. Optional, because not every check has more to
	// say than its sentence.
	Evidence map[string]any `json:"evidence,omitempty"`
}

// Report is the result of running a set of checks for one component.
type Report struct {
	// Component is "controller" or "node-agent".
	Component string `json:"component"`
	// Version is the build metadata of the binary that produced this report, so
	// a report filed against an incident says which build was running.
	Version string `json:"version"`
	// Time is when the report was produced, in UTC.
	Time time.Time `json:"time"`
	// Checks are in declaration order, which is dependency order: a check that
	// another depends on appears first, so reading top-to-bottom gives the causal
	// story rather than an arbitrary one.
	Checks []Check `json:"checks"`
}

// CheckFunc runs one diagnostic. It returns a Check rather than an error so that
// a failing check is a RESULT with evidence, not an exceptional condition — and
// so that a caller cannot accidentally abort the remaining checks by returning
// early.
//
// The name is NOT part of the function's return value: it is declared alongside
// it in a Diagnostic, so the panic-recovery path below can report which check
// died even though the call never returned.
type CheckFunc func(ctx context.Context) Check

// Diagnostic pairs a stable check name with its implementation.
type Diagnostic struct {
	// Name is the stable identifier reported for this check.
	Name string
	// Run performs the check.
	Run CheckFunc
}

// Diagnose declares one diagnostic, so call sites read as a list rather than as
// a series of anonymous closures.
func Diagnose(name string, run CheckFunc) Diagnostic {
	return Diagnostic{Name: name, Run: run}
}

// Run executes every check and collects the results.
//
// A panic in any check is converted into a failed check naming the panic value.
// This is deliberate and load-bearing: doctor is the command an operator runs
// when something is already wrong, and a diagnostic that dies on the first
// broken subsystem reports nothing about the other four.
func Run(ctx context.Context, component, version string, now func() time.Time, diagnostics ...Diagnostic) Report {
	if now == nil {
		now = time.Now
	}
	if ctx == nil {
		ctx = context.Background()
	}
	report := Report{
		Component: component,
		Version:   version,
		Time:      now().UTC(),
		Checks:    make([]Check, 0, len(diagnostics)),
	}
	for _, d := range diagnostics {
		report.Checks = append(report.Checks, safeRun(ctx, d))
	}
	return report
}

// safeRun invokes one check, converting a panic into a failed check.
//
// The name is taken from the Diagnostic rather than from the (never-assigned)
// return value, which is what makes a panicking check identifiable at all.
func safeRun(ctx context.Context, d Diagnostic) (result Check) {
	defer func() {
		if r := recover(); r != nil {
			result = Check{
				Name:   d.Name,
				Status: StatusFail,
				Detail: fmt.Sprintf("the check panicked: %v", r),
				Evidence: map[string]any{
					"panic": fmt.Sprint(r),
					// The first few frames, because "it panicked" alone is not
					// something an operator or a bug report can act on.
					"stack": firstFrames(debug.Stack()),
				},
			}
		}
	}()
	check := d.Run(ctx)
	// A check that returns no name is a programming error in this package, and
	// silently emitting it would produce an unnamed row an operator cannot
	// search for. Naming it explicitly makes the mistake visible in the report.
	if check.Name == "" {
		check.Name = d.Name
	}
	return check
}

// firstFrames trims a goroutine stack to the frames that identify the panic
// site. A full stack in a diagnostic report is mostly runtime internals.
func firstFrames(stack []byte) string {
	lines := strings.Split(string(stack), "\n")
	const keep = 12
	if len(lines) > keep {
		lines = lines[:keep]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// Counts summarizes a report by status.
type Counts struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// Count tallies the report's checks by status.
func (r Report) Count() Counts {
	var c Counts
	for _, check := range r.Checks {
		switch check.Status {
		case StatusOK:
			c.OK++
		case StatusWarn:
			c.Warn++
		case StatusFail:
			c.Fail++
		case StatusSkip:
			c.Skip++
		}
	}
	return c
}

// Healthy reports whether the component can be expected to work: no failed
// checks. Warnings and skips do not make it unhealthy, because a warning is by
// definition survivable and a skip means "not measured", not "broken".
func (r Report) Healthy() bool { return r.Count().Fail == 0 }

// Text renders the report for a human terminal.
func (r Report) Text() string {
	var buf strings.Builder
	r.WriteText(&buf)
	return buf.String()
}

// WriteText renders the report to w.
//
// A tabwriter rather than manual padding: the evidence column varies in width
// between checks, and hand-rolled alignment breaks the moment one name is longer
// than the others.
func (r Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "jawaker %s — %s\n", r.Component, r.Version)
	fmt.Fprintf(w, "checked %s\n\n", r.Time.Format(time.RFC3339))

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, check := range r.Checks {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", statusMark(check.Status), check.Name, check.Detail)
	}
	_ = tw.Flush()

	c := r.Count()
	fmt.Fprintf(w, "\n%d ok", c.OK)
	if c.Warn > 0 {
		fmt.Fprintf(w, ", %d warning", c.Warn)
	}
	if c.Fail > 0 {
		fmt.Fprintf(w, ", %d FAILED", c.Fail)
	}
	if c.Skip > 0 {
		fmt.Fprintf(w, ", %d skipped", c.Skip)
	}
	fmt.Fprintln(w)
}

// statusMark renders a status as a short, greppable word. Deliberately a word
// rather than a symbol: a report is often pasted into an issue tracker that
// renders color codes and box-drawing characters unpredictably.
func statusMark(s Status) string {
	switch s {
	case StatusOK:
		return "ok  "
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "FAIL"
	case StatusSkip:
		return "skip"
	default:
		return string(s)
	}
}

// JSON renders the report as indented JSON for machine consumption.
func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ok builds a passing check.
func ok(name, detail string, evidence map[string]any) Check {
	return Check{Name: name, Status: StatusOK, Detail: detail, Evidence: evidence}
}

// warn builds a warning check.
func warn(name, detail string, evidence map[string]any) Check {
	return Check{Name: name, Status: StatusWarn, Detail: detail, Evidence: evidence}
}

// fail builds a failing check.
func fail(name, detail string, evidence map[string]any) Check {
	return Check{Name: name, Status: StatusFail, Detail: detail, Evidence: evidence}
}

// skip builds a check that could not run.
//
// No evidence parameter: every skip so far is "the precondition was absent", and
// the absent thing is already named in detail. A check that needs to attach
// evidence can return a Check literal instead of growing this signature.
func skip(name, detail string) Check {
	return Check{Name: name, Status: StatusSkip, Detail: detail}
}
