package nodeagent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// HostMetrics samples CPU, memory, disk and load for Phase 7 observability.
// Linux-only: the sources are /proc and statfs. The parse helpers below are
// plain functions over byte content so tests run on any platform with fixtures.
func (e *Executors) HostMetrics(ctx context.Context, _ nodewire.NodeMetricsInput) (nodewire.NodeMetricsResult, error) {
	if runtime.GOOS != "linux" {
		return nodewire.NodeMetricsResult{}, notAvailable("host metrics are supported on Linux only")
	}

	// CPU percentage is a delta: two /proc/stat reads 200ms apart. Shorter
	// windows measure scheduler noise; longer ones delay the op past its
	// usefulness for a 60s sampling cadence.
	first, err := readProcStatCPU()
	if err != nil {
		return nodewire.NodeMetricsResult{}, err
	}
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nodewire.NodeMetricsResult{}, ctx.Err()
	case <-timer.C:
	}
	second, err := readProcStatCPU()
	if err != nil {
		return nodewire.NodeMetricsResult{}, err
	}

	mem, err := readProcMemInfo()
	if err != nil {
		return nodewire.NodeMetricsResult{}, err
	}
	load, err := readProcLoadavg()
	if err != nil {
		return nodewire.NodeMetricsResult{}, err
	}
	disk, err := statfsRootPct()
	if err != nil {
		return nodewire.NodeMetricsResult{}, err
	}

	return nodewire.NodeMetricsResult{
		CPUPct:     cpuPctBetween(first, second),
		MemPct:     mem,
		DiskPct:    disk,
		Load1:      load,
		ObservedAt: e.now(),
	}, nil
}

// cpuSample is one read of /proc/stat's aggregate "cpu " line, in jiffies.
type cpuSample struct {
	total float64
	idle  float64 // idle + iowait
}

// parseCPUStat extracts the aggregate cpu line. Fields (Linux >= 2.6):
// user nice system idle iowait irq softirq steal guest guest_nice.
func parseCPUStat(content []byte) (cpuSample, error) {
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		if !bytes.HasPrefix(sc.Bytes(), []byte("cpu ")) {
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			return cpuSample{}, fmt.Errorf("cpu line has %d fields, want >= 5", len(fields))
		}
		var s cpuSample
		for i, f := range fields[1:] {
			v, err := strconv.ParseFloat(f, 64)
			if err != nil {
				return cpuSample{}, fmt.Errorf("cpu field %d %q: %w", i, f, err)
			}
			s.total += v
			if i == 3 || i == 4 { // idle, iowait
				s.idle += v
			}
		}
		return s, nil
	}
	if err := sc.Err(); err != nil {
		return cpuSample{}, err
	}
	return cpuSample{}, fmt.Errorf("no aggregate cpu line in /proc/stat content")
}

// cpuPctBetween computes busy percentage between two samples, clamped 0..100.
// A non-positive delta (clock stood still between reads) reports 0 rather than
// NaN — NaN would fail wire validation and kill the sample for a benign case.
func cpuPctBetween(a, b cpuSample) float64 {
	dTotal, dIdle := b.total-a.total, b.idle-a.idle
	if dTotal <= 0 {
		return 0
	}
	return clampPct((dTotal - dIdle) / dTotal * 100)
}

// parseMemInfo computes used memory percentage from MemTotal and MemAvailable,
// falling back to MemFree on kernels without MemAvailable (< 3.14).
func parseMemInfo(content []byte) (float64, error) {
	var totalK float64
	availK := -1.0
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalK = v
		case "MemAvailable:":
			availK = v
		case "MemFree:":
			if availK < 0 {
				availK = v
			}
		}
	}
	if totalK <= 0 {
		return 0, fmt.Errorf("no MemTotal in /proc/meminfo content")
	}
	if availK < 0 {
		availK = 0
	}
	return clampPct((totalK - availK) / totalK * 100), nil
}

// parseLoadavg returns the one-minute load average (first field).
func parseLoadavg(content []byte) (float64, error) {
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/loadavg content")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("loadavg field %q: %w", fields[0], err)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("loadavg %g is not finite", v)
	}
	return v, nil
}

func clampPct(v float64) float64 {
	return math.Max(0, math.Min(100, v))
}
