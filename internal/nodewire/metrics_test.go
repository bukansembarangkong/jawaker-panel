package nodewire

import (
	"math"
	"testing"
	"time"
)

func TestNodeMetricsResultValidate(t *testing.T) {
	ok := NodeMetricsResult{CPUPct: 12.5, MemPct: 60, DiskPct: 75, Load1: 2.4, ObservedAt: time.Now()}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}

	bad := []struct {
		name string
		r    NodeMetricsResult
	}{
		{"cpu over 100", NodeMetricsResult{CPUPct: 101, MemPct: 1, DiskPct: 1, Load1: 1, ObservedAt: time.Now()}},
		{"mem negative", NodeMetricsResult{CPUPct: 1, MemPct: -2, DiskPct: 1, Load1: 1, ObservedAt: time.Now()}},
		{"disk NaN", NodeMetricsResult{CPUPct: 1, MemPct: 1, DiskPct: math.NaN(), Load1: 1, ObservedAt: time.Now()}},
		{"load1 Inf", NodeMetricsResult{CPUPct: 1, MemPct: 1, DiskPct: 1, Load1: math.Inf(1), ObservedAt: time.Now()}},
		{"zero observed_at", NodeMetricsResult{CPUPct: 1, MemPct: 1, DiskPct: 1, Load1: 1}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.r.Validate(); err == nil {
				t.Error("want validation error")
			}
		})
	}
}

func TestNodeMetricsInputValidate(t *testing.T) {
	if err := (NodeMetricsInput{}).Validate(); err != nil {
		t.Errorf("empty input must validate: %v", err)
	}
}
