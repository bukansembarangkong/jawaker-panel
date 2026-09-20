//go:build linux

package doctor

import (
	"math"
	"syscall"
)

// diskFree reports the free and total bytes on the filesystem holding path.
//
// Statfs rather than shell-out to `df`: a diagnostic must not depend on an
// external binary being present, and on a broken host the PATH it inherits is
// exactly the kind of thing that cannot be trusted.
func diskFree(path string) (free, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	// Bavail (unprivileged-available) rather than Bfree (total-free), because
	// the difference is the filesystem's root reserve: reporting Bfree would
	// claim space the controller process cannot actually use.
	return saturatingBytes(st.Bavail, st.Bsize), saturatingBytes(st.Blocks, st.Bsize), nil
}

// saturatingBytes multiplies two unsigned filesystem counts into a signed byte
// total, clamping rather than wrapping.
//
// THE CLAMP IS THE POINT. Statfs counts are uint64 and a byte total is int64, so
// a naive conversion wraps to a NEGATIVE size — which would report a full disk as
// an empty one, inverting the meaning of the only check that exists to warn about
// a full disk. Clamping at MaxInt64 cannot be reached by a real filesystem, and
// if it somehow were, "inconceivably large" is a far safer thing to report.
func saturatingBytes(count uint64, blockSize int64) int64 {
	if count == 0 || blockSize <= 0 {
		return 0
	}
	// Compute the product in uint64 and compare BEFORE converting, so the
	// conversion below is provably in range rather than merely believed to be.
	blocks := uint64(blockSize)
	if count > math.MaxUint64/blocks {
		// The multiplication itself would wrap in uint64.
		return math.MaxInt64
	}
	product := count * blocks
	if product > uint64(math.MaxInt64) {
		return math.MaxInt64
	}
	// product <= MaxInt64 is established by the check immediately above, so this
	// conversion cannot overflow. gosec cannot see that invariant, hence the
	// annotation: the guard is two lines up, not hypothetical.
	return int64(product) //nolint:gosec // G115: guarded above; product is proven <= MaxInt64
}
