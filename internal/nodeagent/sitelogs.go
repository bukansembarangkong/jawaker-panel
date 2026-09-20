package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// Site log read-through: the code that serves site.logs.tail.
//
// Per D-005 (docs/decisions.md): site logs are read from the node on demand.
// No log content is ever written to the control-plane database.
//
// Per D-006: the permission is site.logs.read (project-scoped), not logs.read
// (server-scoped).
//
// The log file path is DERIVED by the agent from the slugs the caller supplies
// using the canonical layout from D-001:
//
//	/var/log/nginx/<project_slug>--<site_slug>-<log_type>.log
//
// The caller has no way to choose a file or a directory. The only
// trust boundary is the confinement check against /var/log/nginx, which the
// scope.go code enforces by resolving symlinks.

// defaultNginxLogRoot is the directory the operation is confined to by default.
const defaultNginxLogRoot = "/var/log/nginx"

// SiteLogs reads the tail of one site's nginx log file.
//
// The path is agent-derived: the caller names WHAT it wants (project, site,
// log type) and the agent decides WHERE. That distinction is what keeps this a
// typed log-read and not a generic file-read primitive.
func (e *Executors) SiteLogs(ctx context.Context, in nodewire.SiteLogsTailInput) (nodewire.SiteLogsTailResult, error) {
	var out nodewire.SiteLogsTailResult

	if err := in.Validate(); err != nil {
		return out, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: err.Error(),
		}
	}

	// Agent derives the path: <root>/<project>--<site>-<type>.log
	// The slug regex on both slugs has already been checked by Validate(), so
	// they cannot contain separators, NUL bytes, or shell metacharacters. The
	// explicit path join below still goes through confinement; the prior
	// validation is the fast path that names the offending value.
	logRoot := e.logDir
	if logRoot == "" {
		logRoot = defaultNginxLogRoot
	}
	filename := in.ProjectSlug + "--" + in.SiteSlug + "-" + in.LogType + ".log"
	rawPath := filepath.Join(logRoot, filename)

	conf, err := newConfinement([]string{logRoot})
	if err != nil {
		// The log root itself is not usable on this host.
		return out, &nodewire.Error{
			Code:    nodewire.CodeNotAvailable,
			Message: "the nginx log directory is not accessible on this host",
		}
	}

	// For reads (as opposed to writes) we use the read-confinement check: verify
	// the resolved path is inside the root. confinement.resolve() is designed for
	// WRITE targets (it rejects symlinks for the final component), which is
	// intentionally strict. For reads a symlinked log file would be valid,
	// however the file must still be within the root after full resolution.
	// We use a direct check here to be equally strict: we resolve the path fully
	// and confirm it stays inside the root.
	cleanPath := filepath.Clean(rawPath)
	realPath, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No log file yet for this site: return empty rather than an error.
			// A site that has been created but never served has no log file, and
			// that is not a failure.
			out.LogType = in.LogType
			out.ObservedAt = e.now().UTC()
			return out, nil
		}
		return out, &nodewire.Error{
			Code:    nodewire.CodeNotFound,
			Message: "the site log file is not accessible on this host",
		}
	}
	if !conf.contains(realPath) {
		// The resolved path is outside the root. This is a bug in the slug
		// validation or a crafted filename; either way it is a scope violation.
		return out, &nodewire.Error{
			Code:    nodewire.CodeScopeViolation,
			Message: "the derived log path is outside the permitted scope",
		}
	}

	n := in.Lines
	if n == 0 {
		n = nodewire.DefaultSiteLogsTailLines
	}

	lines, truncated, err := tailFile(ctx, realPath, n)
	if err != nil {
		return out, &nodewire.Error{
			Code:      nodewire.CodeExecutionFailed,
			Message:   "the site log file could not be read",
			Retryable: true,
		}
	}

	out.Lines = lines
	out.Truncated = truncated
	out.LogType = in.LogType
	out.ObservedAt = e.now().UTC()
	return out, nil
}

// tailFile reads at most maxLines trailing lines from the file at path, subject
// to the MaxSiteLogsTailBytes wire budget.
//
// It seeks to the end of the file, reads a bounded block back, and splits on
// newlines — no shell process is spawned. The approach is:
//
//  1. Open the file read-only.
//  2. Seek to max(0, end - MaxSiteLogsTailBytes). If the file is smaller than
//     the budget the whole file is read and Truncated is false.
//  3. Split the read buffer on newlines.
//  4. Keep the last maxLines from that split.
//  5. Truncated is true if either of the two bounds triggered.
//
// NUL bytes are filtered because a log file with NUL may have been truncated or
// rotated mid-byte; they cannot occur in a valid text log line.
func tailFile(_ context.Context, path string, maxLines int) (lines []string, truncated bool, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is confined and slug-validated
	if err != nil {
		return nil, false, fmt.Errorf("open log: %w", err)
	}
	defer func() { _ = f.Close() }()

	size, err := f.Seek(0, 2) // seek to end
	if err != nil {
		return nil, false, fmt.Errorf("seek log end: %w", err)
	}

	// How far back do we seek to read the budget window?
	start := size - nodewire.MaxSiteLogsTailBytes
	if start < 0 {
		start = 0
	} else {
		truncated = true // we are reading a suffix, not the whole file
	}

	if _, err = f.Seek(start, 0); err != nil {
		return nil, false, fmt.Errorf("seek log start: %w", err)
	}

	buf := make([]byte, size-start)
	n, err := f.Read(buf)
	if err != nil {
		return nil, false, fmt.Errorf("read log: %w", err)
	}
	buf = buf[:n]

	// Strip NUL bytes. A valid text log cannot have NUL; their presence means
	// a partial write or a binary file was pointed at by accident.
	buf = []byte(strings.ReplaceAll(string(buf), "\x00", ""))

	// Split. We may have started mid-line if we truncated; if so the first entry
	// is partial. We discard it only when we know we did not read from the start
	// of the file — if we read the whole file, partial lines at line 0 are real.
	rawLines := strings.Split(string(buf), "\n")

	// Remove the trailing empty element that always appears when the file ends
	// with a newline.
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}

	// If we truncated (did not start at byte 0), the first rawLine is partial.
	if truncated && len(rawLines) > 0 {
		rawLines = rawLines[1:]
	}

	// Keep the last maxLines.
	if len(rawLines) > maxLines {
		rawLines = rawLines[len(rawLines)-maxLines:]
		truncated = true
	}

	return rawLines, truncated, nil
}
