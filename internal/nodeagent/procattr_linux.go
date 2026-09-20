//go:build linux

package nodeagent

import "syscall"

// processGroupAttr puts a spawned child into its OWN process group.
//
// This is what makes cancellation mean something. Go's exec.CommandContext kills
// only the process it started; a command that forks (systemctl talks to a daemon,
// and anything that shells out spawns children) leaves orphans running after the
// deadline. Killing the process GROUP reaches all of them.
//
// It is also what keeps the agent's own group safe: without Setpgid the child
// shares the agent's group, and a kill of the child's group would take the agent
// down with it.
func processGroupAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup terminates the group led by pid.
//
// The negative pid is the POSIX way to address a process group. SIGKILL rather
// than SIGTERM because this runs only after the context deadline has already
// expired: the polite signal was the cancellation, and by now the operation is
// out of time. Escalation is the point.
func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}
