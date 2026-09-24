// Package resourceprofile detects host capacity and computes adaptive resource budgets
// per PRD §31 (Performance and Resource Budgets).
package resourceprofile

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// ProfileName is the tier classification per PRD §31.1.
type ProfileName string

const (
	ProfileTiny   ProfileName = "tiny"   // ~1 CPU / 1 GB RAM
	ProfileSmall  ProfileName = "small"  // ~2 CPU / 2-4 GB RAM
	ProfileMedium ProfileName = "medium" // ~4 CPU / 8 GB RAM
	ProfileLarge  ProfileName = "large"  // 8+ CPU / 16+ GB RAM
)

// Budget holds adaptive parameters tuned for the host capacity per PRD §31.2.
type Budget struct {
	Profile                ProfileName `json:"profile"`
	CPUs                   int         `json:"cpus"`
	TotalRAMMB             int         `json:"total_ram_mb"`
	WorkerConcurrency      int         `json:"worker_concurrency"`
	JobConcurrency         int         `json:"job_concurrency"`
	MetricsIntervalSeconds int         `json:"metrics_interval_seconds"`
	LogRetentionDays       int         `json:"log_retention_days"`
	AnalyticsEnabled       bool        `json:"analytics_enabled"`
}

// Current returns the budget appropriate for the host machine.
func Current() Budget {
	cpus := runtime.NumCPU()
	ramMB := readTotalRAMMB()
	return Classify(cpus, ramMB)
}

// Classify determines the adaptive profile from CPU count and RAM in megabytes.
func Classify(cpus, ramMB int) Budget {
	var p ProfileName
	switch {
	case cpus >= 8 && ramMB >= 14000:
		p = ProfileLarge
	case cpus >= 4 && ramMB >= 6000:
		p = ProfileMedium
	case cpus >= 2 && ramMB >= 1800:
		p = ProfileSmall
	default:
		p = ProfileTiny
	}

	b := Budget{
		Profile:    p,
		CPUs:       cpus,
		TotalRAMMB: ramMB,
	}

	switch p {
	case ProfileLarge:
		b.WorkerConcurrency = 8
		b.JobConcurrency = 4
		b.MetricsIntervalSeconds = 10
		b.LogRetentionDays = 30
		b.AnalyticsEnabled = true
	case ProfileMedium:
		b.WorkerConcurrency = 4
		b.JobConcurrency = 2
		b.MetricsIntervalSeconds = 15
		b.LogRetentionDays = 14
		b.AnalyticsEnabled = true
	case ProfileSmall:
		b.WorkerConcurrency = 2
		b.JobConcurrency = 1
		b.MetricsIntervalSeconds = 30
		b.LogRetentionDays = 7
		b.AnalyticsEnabled = false
	default: // Tiny
		b.WorkerConcurrency = 1
		b.JobConcurrency = 1
		b.MetricsIntervalSeconds = 60
		b.LogRetentionDays = 3
		b.AnalyticsEnabled = false
	}

	return b
}

func readTotalRAMMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		// Fallback when /proc/meminfo is not available (e.g. Windows/macOS in dev)
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		// Return 4 GB default fallback for development
		return 4096
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.Atoi(fields[1])
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 2048
}
