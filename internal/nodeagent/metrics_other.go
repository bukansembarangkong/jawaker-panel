//go:build !linux

package nodeagent

import "errors"

// Non-Linux stubs. HostMetrics refuses before reaching these (runtime guard),
// so they exist only to keep the package compiling on every platform — the
// CI distro matrix builds Windows/macOS binaries of the agent.
var errMetricsUnsupported = errors.New("host metrics are supported on Linux only")

func readProcStatCPU() (cpuSample, error) { return cpuSample{}, errMetricsUnsupported }
func readProcMemInfo() (float64, error)   { return 0, errMetricsUnsupported }
func readProcLoadavg() (float64, error)   { return 0, errMetricsUnsupported }
func statfsRootPct() (float64, error)     { return 0, errMetricsUnsupported }
