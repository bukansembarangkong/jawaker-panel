//go:build !linux

package nodeagent

import (
	"errors"
	"syscall"
)

// processGroupAttr is a no-op off Linux.
//
// The agent declares Linux-only OS support in every operation descriptor, and
// the runner refuses service.* operations when systemd is absent. This stub
// exists so the package still COMPILES and its logic stays testable elsewhere —
// notably on a developer's machine, which is how the operation-dispatch and
// refusal paths get exercised without a Linux host or a container.
//
// It is not a claim of support. A build that reached this file would be running
// an agent that cannot supervise a child properly, which is why the server
// refuses mutating operations when this build's OS is not Linux (see
// supportedOS), rather than proceeding with weaker guarantees.
func processGroupAttr() *syscall.SysProcAttr {
	return nil
}

// killProcessGroup cannot address a group here; see the note above.
func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	return errors.New("nodeagent: process group kill is only available on linux")
}
