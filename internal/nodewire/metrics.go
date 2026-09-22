package nodewire

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// NodeMetricsInput is empty — the node samples its host, no parameters needed.
// It exists so the wire format stays explicit and future knobs (paths, net
// interfaces) have a home without a protocol break.
type NodeMetricsInput struct{}

// Validate satisfies the payload contract.
func (NodeMetricsInput) Validate() error { return nil }

// NodeMetricsResult is one point-in-time host sample. Percentages are 0..100;
// load1 is the one-minute load average (unitless, can exceed 1 on busy hosts).
// ObservedAt is the node's timestamp at sample time so the controller can
// detect clock drift rather than trusting its own clock.
type NodeMetricsResult struct {
	CPUPct     float64   `json:"cpu_pct"`
	MemPct     float64   `json:"mem_pct"`
	DiskPct    float64   `json:"disk_pct"`
	Load1      float64   `json:"load1"`
	ObservedAt time.Time `json:"observed_at"`
}

// Validate rejects NaN/Inf and percentages outside 0..100. Load1 is only
// checked for finiteness: it is legitimately unbounded.
func (r NodeMetricsResult) Validate() error {
	for _, p := range []struct {
		name string
		pct  float64
	}{{"cpu", r.CPUPct}, {"mem", r.MemPct}, {"disk", r.DiskPct}} {
		if math.IsNaN(p.pct) || math.IsInf(p.pct, 0) || p.pct < 0 || p.pct > 100 {
			return fmt.Errorf("nodewire: %s percent must be a finite value in [0,100], got %g", p.name, p.pct)
		}
	}
	if math.IsNaN(r.Load1) || math.IsInf(r.Load1, 0) {
		return errors.New("nodewire: load1 must be finite")
	}
	if r.ObservedAt.IsZero() {
		return errors.New("nodewire: observed_at is required")
	}
	return nil
}
