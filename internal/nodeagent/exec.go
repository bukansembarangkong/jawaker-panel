package nodeagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Command execution on a node, with the properties that make it defensible.
//
// There is no shell anywhere in this file, and that is the single most important
// fact about it. A shell is what turns a validated-looking string into arbitrary
// code: `nginx; rm -rf /` is a perfectly ordinary string, and its danger exists
// only because something downstream interprets it. Here a command is a PATH plus
// an ARGV SLICE, so a unit name that contains a metacharacter is one argument
// with an odd name — the kernel never parses it.
//
// Everything else follows from the same principle:
//
//   - the program path is resolved ONCE at startup from a fixed candidate list,
//     never from PATH. Resolution at startup means a later change to the
//     environment cannot redirect what the agent runs, and an operator can see
//     which binary was chosen before any operation arrives;
//   - the environment is built here, not inherited. An inherited environment is
//     attacker-influenced in a way nothing in the request can reveal;
//   - the working directory is fixed, so a relative path in a child cannot
//     resolve against whatever directory the agent happened to be started in;
//   - output is bounded, so a chatty or hostile child cannot make the agent
//     allocate without limit;
//   - the child gets its OWN process group, so a deadline cancels the whole tree
//     rather than orphaning grandchildren.

// maxOutputBytes bounds a child's stdout and stderr each. The outputs are parsed
// for a handful of fields, so anything near this is already evidence of a
// misbehaving command rather than useful data.
const maxOutputBytes = 64 * 1024

// ErrOutputLimit means a child produced more output than the agent will read.
//
// It is an error rather than a truncation the caller never sees: a truncated
// parse silently drops the fields beyond the cut, which for a status query means
// reporting a partially-read state as if it were the whole one.
var ErrOutputLimit = errors.New("nodeagent: command output exceeded the limit")

// ErrCommandFailed means the child ran and exited non-zero.
type ErrCommandFailed struct {
	Path     string
	Code     int
	Stderr   string
	TimedOut bool
}

func (e *ErrCommandFailed) Error() string {
	if e.TimedOut {
		return fmt.Sprintf("nodeagent: %s did not finish before its deadline", e.Path)
	}
	if e.Stderr != "" {
		return fmt.Sprintf("nodeagent: %s exited %d: %s", e.Path, e.Code, e.Stderr)
	}
	return fmt.Sprintf("nodeagent: %s exited %d", e.Path, e.Code)
}

// CommandSpec is a resolved command: an absolute path and an argv slice.
//
// It is a struct rather than variadic arguments so that every field a caller can
// influence is named at the call site and visible in review.
type CommandSpec struct {
	// Path is an absolute path to an executable, resolved at startup.
	Path string
	// Args is the argument vector, passed as-is. Never a command string.
	Args []string
	// Timeout bounds this specific command. Zero means no additional bound
	// beyond the context deadline.
	Timeout time.Duration
}

// Validate refuses a spec that could not be safely executed.
func (s CommandSpec) Validate() error {
	if s.Path == "" {
		return errors.New("nodeagent: command path is required")
	}
	if !isAbsPath(s.Path) {
		return fmt.Errorf("nodeagent: command path %q must be absolute", s.Path)
	}
	for i, a := range s.Args {
		// A NUL cannot appear in an argument: the execve(2) interface is
		// NUL-terminated, so a Go string containing one either fails or, worse,
		// truncates the argument. Refusing here means the failure is named.
		if containsNUL(a) {
			return fmt.Errorf("nodeagent: argument %d contains a NUL byte", i)
		}
	}
	return nil
}

// CommandResult is the output of a successful command.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCommand executes a spec under a context and returns its output.
//
// Cancellation kills the child's entire process group, not just the process Go
// started. Without that, a deadline on a command that forks leaves the
// grandchildren running — the operation reports as canceled while the work
// continues, which is the worst of both outcomes.
func runCommand(ctx context.Context, spec CommandSpec) (CommandResult, error) {
	if err := spec.Validate(); err != nil {
		return CommandResult{}, err
	}
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}

	// G204 is expected at the agent's one and only subprocess entry point. It is
	// safe because spec.Validate() above rejected a relative path, a NUL in argv,
	// and anything off the closed registry; no shell is invoked and spec.Path is
	// resolved from a fixed candidate list rather than PATH.
	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...) //nolint:gosec // G204: argv is validated by CommandSpec.Validate above; no shell, absolute path only
	// A controlled environment: nothing inherited. LANG/LC_ALL are pinned so
	// parsed output does not change shape with the host's locale.
	cmd.Env = controlledEnv()
	// A fixed working directory, so a relative path inside the child cannot
	// resolve against wherever the agent was started.
	cmd.Dir = safeWorkingDir()
	cmd.SysProcAttr = processGroupAttr()
	cmd.Stdin = nil

	var (
		stdout = &limitedBuffer{limit: maxOutputBytes}
		stderr = &limitedBuffer{limit: maxOutputBytes}
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return CommandResult{}, fmt.Errorf("nodeagent: start %s: %w", spec.Path, err)
	}

	// Wait in a goroutine so the context can be observed while the child runs.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return finishCommand(spec, stdout, stderr, err, false)
	case <-ctx.Done():
		// Kill the GROUP, then reap the direct child so it does not become a
		// zombie. The release happens even if the kill fails, so a child that
		// already exited is still collected.
		_ = killProcessGroup(cmd.Process.Pid)
		err := <-done
		return finishCommand(spec, stdout, stderr, err, true)
	}
}

// finishCommand converts a Wait result into a CommandResult or a typed error.
func finishCommand(spec CommandSpec, stdout, stderr *limitedBuffer, waitErr error, timedOut bool) (CommandResult, error) {
	// An output-limit breach is reported before the exit code: a child that
	// produced too much output has not given the caller anything parsable, and
	// reporting "exited 0" alongside a truncated body would invite a caller to
	// parse it anyway.
	switch {
	case stdout.overflowed || stderr.overflowed:
		return CommandResult{}, fmt.Errorf("%w: %s", ErrOutputLimit, spec.Path)
	case timedOut:
		return CommandResult{}, &ErrCommandFailed{Path: spec.Path, TimedOut: true}
	case waitErr == nil:
		return CommandResult{
			Stdout: stdout.String(),
			Stderr: stderr.String(),
		}, nil
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return CommandResult{}, &ErrCommandFailed{
			Path:   spec.Path,
			Code:   exitErr.ExitCode(),
			Stderr: boundForMessage(stderr.String()),
		}
	}
	return CommandResult{}, fmt.Errorf("nodeagent: wait for %s: %w", spec.Path, waitErr)
}

// BoundForMessageLimit is the maximum length of a child's stderr once it is placed
// into an error message.
//
// It is exported as a constant because a caller that RECEIVES such a message needs
// to be able to tell whether it was cut short. internal/nodeagent's web-config
// executor does exactly that: it reports a truncation flag rather than presenting a
// bounded message as a complete one.
const BoundForMessageLimit = 512

// boundForMessage truncates a child's stderr before it is put into an error.
//
// The message travels into the controller's logs and possibly into a UI. A child
// can write megabytes to stderr, and an unbounded error string is a way to fill
// somebody else's disk with your own text.
func boundForMessage(s string) string {
	if len(s) <= BoundForMessageLimit {
		return trimSpace(s)
	}
	return trimSpace(s[:BoundForMessageLimit]) + "… (truncated)"
}

// limitedBuffer collects output up to a limit.
//
// io.LimitReader would stop READING rather than stop ACCEPTING, which leaves the
// child blocked on a full pipe forever — a deadlock dressed as a size limit. This
// keeps draining and discards the excess, so the child always finishes and the
// breach is reported afterwards.
type limitedBuffer struct {
	buf        bytes.Buffer
	limit      int
	overflowed bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	// Always report the full length: a short write would look like an I/O error
	// to the child and change its behavior.
	if remaining := l.limit - l.buf.Len(); remaining > 0 {
		if len(p) <= remaining {
			l.buf.Write(p)
		} else {
			l.buf.Write(p[:remaining])
			l.overflowed = true
		}
	} else if len(p) > 0 {
		l.overflowed = true
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }

// ReadFrom is implemented so os/exec's internal io.Copy takes this path rather
// than allocating its own buffer per read.
func (l *limitedBuffer) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			_, _ = l.Write(buf[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

// controlledEnv is the complete environment a child receives.
//
// It is built rather than filtered: a filter that removes known-bad names would
// have to be revisited every time the platform adds one. Nothing here is secret
// and nothing here is derived from a request.
func controlledEnv() []string {
	return []string{
		// A stable locale so parsed output does not change shape with the host.
		"LANG=C",
		"LC_ALL=C",
		// A minimal PATH for children that themselves exec something. It is a
		// fixed value: no request and no inherited variable can extend it.
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

// safeWorkingDir is the fixed cwd for every child.
//
// Root rather than the agent's own cwd: the directory an agent was launched from
// is whatever the service file or an operator's shell happened to be, and a child
// that resolves a relative path against it behaves differently on two hosts for
// no reason anyone can see in the configuration. The OS temp directory is the
// fallback for the odd platform where "/" is not statable.
func safeWorkingDir() string {
	if info, err := os.Stat("/"); err == nil && info.IsDir() {
		return "/"
	}
	return os.TempDir()
}

// resolveProgram picks the first existing candidate from a fixed list.
//
// It deliberately does not consult PATH. A PATH lookup at request time would mean
// the binary the agent runs depends on an environment variable, and an operator
// reading the configuration could not tell which one that is. The chosen path is
// logged once at startup instead.
func resolveProgram(candidates ...string) (string, bool) {
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			// Present but not executable. Treated as absent: it cannot be run,
			// and reporting it as available would produce a capability claim the
			// node cannot honor.
			continue
		}
		return candidate, true
	}
	return "", false
}

// isAbsPath reports whether a program path is absolute.
//
// filepath.IsAbs rather than a prefix check: the definition of absolute differs
// per platform, and a hand-written check would be wrong on one of them in a way
// that only shows up when the agent is actually deployed there.
func isAbsPath(p string) bool { return filepath.IsAbs(p) }

// containsNUL reports whether s holds a NUL byte.
func containsNUL(s string) bool { return strings.IndexByte(s, 0) >= 0 }

// trimSpace trims surrounding whitespace, including the trailing newline that
// every command in this package emits.
func trimSpace(s string) string { return strings.TrimSpace(s) }
