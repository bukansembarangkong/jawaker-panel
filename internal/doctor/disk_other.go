//go:build !linux

package doctor

import "errors"

// diskFree is unavailable off Linux.
//
// Returning an error rather than a zero figure is deliberate: the caller reports
// a SKIP naming the reason, so an operator sees "free-space reporting is not
// implemented on this platform" instead of "0 bytes free", which would read as a
// full disk and send them hunting for something that is not wrong.
func diskFree(string) (int64, int64, error) {
	return 0, 0, errors.New("doctor: free-space reporting is not implemented on this platform")
}
