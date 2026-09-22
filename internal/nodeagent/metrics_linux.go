//go:build linux

package nodeagent

import (
	"fmt"
	"os"
	"syscall"
)

// readProcStatCPU reads the aggregate cpu line of /proc/stat.
func readProcStatCPU() (cpuSample, error) {
	content, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	return parseCPUStat(content)
}

// readProcMemInfo computes used-memory percentage from /proc/meminfo.
func readProcMemInfo() (float64, error) {
	content, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	return parseMemInfo(content)
}

// readProcLoadavg returns the one-minute load average from /proc/loadavg.
func readProcLoadavg() (float64, error) {
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	return parseLoadavg(content)
}

// statfsRootPct returns root-filesystem used percentage.
//
// ponytail: only "/" is sampled — the panel's storage-pressure story is the
// root volume (sites, backups, logs all live under it). Upgrade path: accept a
// mount list in NodeMetricsInput when a node legitimately spans volumes.
func statfsRootPct() (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, fmt.Errorf("statfs /: %w", err)
	}
	total := st.Blocks * uint64(st.Bsize)
	if total == 0 {
		return 0, fmt.Errorf("statfs / reports zero blocks")
	}
	// df semantics: used = total - free, percentage against used + available
	// so root-reserved blocks are excluded from both sides.
	free := st.Bfree * uint64(st.Bsize)
	avail := st.Bavail * uint64(st.Bsize)
	used := total - free
	denom := used + avail
	if denom == 0 {
		return 0, nil
	}
	return clampPct(float64(used) / float64(denom) * 100), nil
}
