//go:build linux

package doctor

import (
	"math"
	"testing"
)

// The conversion from Statfs counts to a signed byte total must CLAMP, not wrap.
//
// A wrap would produce a negative "free" figure, which reads as an empty disk and
// inverts the check's meaning: the one condition it exists to report would become
// the one it reports as fine. This is asserted rather than left to the type
// system, because the overflow is silent in Go.
func TestDiskByteConversionClampsRatherThanWrapping(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     uint64
		blockSize int64
		want      int64
	}{
		{"zero count", 0, 4096, 0},
		{"zero block size", 100, 0, 0},
		{"negative block size", 100, -1, 0},
		{"ordinary filesystem", 1 << 20, 4096, int64(1<<20) * 4096},
		{"would overflow", math.MaxUint64, 4096, math.MaxInt64},
		{"just over the boundary", uint64(math.MaxInt64)/4096 + 1, 4096, math.MaxInt64},
		{"exactly the boundary", uint64(math.MaxInt64) / 4096, 4096, int64(uint64(math.MaxInt64) / 4096 * 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := saturatingBytes(tc.count, tc.blockSize)
			if got != tc.want {
				t.Errorf("saturatingBytes(%d, %d) = %d, want %d", tc.count, tc.blockSize, got, tc.want)
			}
			// The property that matters regardless of the exact figure: the
			// result is never negative.
			if got < 0 {
				t.Errorf("saturatingBytes returned a NEGATIVE size (%d); a full disk would read as an empty one", got)
			}
		})
	}
}
