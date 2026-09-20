package doctor

import (
	"fmt"
	"time"
)

// humanBytes renders a byte count for a human.
//
// Binary units (KiB/MiB/GiB) rather than decimal, because every filesystem tool
// an operator compares this against reports binary units, and a report that
// disagrees with `df` by 7% is a report that gets ignored.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f EiB", value)
}

// remaining renders a duration until expiry as a coarse, human phrase.
//
// Days rather than a precise duration, because "719h59m12.4s" is harder to read
// than "29 days" and no decision turns on the difference.
func remaining(d time.Duration) string {
	switch {
	case d <= 0:
		return "expired"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
