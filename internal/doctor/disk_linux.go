//go:build linux

package doctor

import "syscall"

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
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}
