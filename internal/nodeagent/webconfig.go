package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// Web-server configuration validation.
//
// This is the first executor that WRITES a file, and the first that runs a
// privileged program against content a caller supplied. Both facts shape it.
//
// The safety property it must have, stated plainly: VALIDATING A CANDIDATE MUST
// NOT BE ABLE TO AFFECT WHAT A RUNNING SITE SERVES. That is why the candidate is
// staged in a directory of its own, validated there with `nginx -t`, and removed,
// and why the live configuration tree is never opened for writing. The descriptor
// declares the two scopes separately and the confinement enforces both, so the
// guarantee is a property of the code rather than of this comment.
//
// Two ceilings meet here and they are different ceilings. nodewire caps the
// REQUEST at 64 KiB; exec.go caps a child's stdout and stderr at 64 KiB each and
// treats exceeding it as an ERROR, not a truncation. nginx -t on a large
// configuration can emit more than that, and failing the whole validation because
// the error message was long would be the wrong outcome — so the output is read
// through a bounded buffer that truncates deliberately and says so.

// nginxBinaryCandidates is the fixed set of paths nginx may be at. Like
// systemdCandidates this is deliberately NOT derived from PATH: a privileged
// program resolved through a user-controlled PATH is a way to run a different
// program than the one that was reviewed.
var nginxBinaryCandidates = []string{"/usr/sbin/nginx", "/usr/bin/nginx", "/sbin/nginx"}

// defaultStagingDir is where a candidate is written before validation. It is
// declared in the descriptor's write scope, so this is the one directory the
// operation may touch.
const defaultStagingDir = "/etc/nginx/jawaker/staging"

// validationOutputLimit bounds what is returned to the controller. It is smaller
// than exec.go's 64 KiB per-stream cap on purpose: this value travels back over
// the wire inside the reply envelope, and the reply is bound by the same kind of
// size discipline as the request.
const validationOutputLimit = 8 * 1024

// WebServer describes the detected web server.
type WebServer struct {
	// Path is the resolved binary, empty when none was found.
	Path string
	// Version is the reported version, best-effort.
	Version string
	// StagingDir is where candidates are staged. It must exist: this code never
	// creates a directory tree, because a directory appearing as a side effect
	// of a validation is a filesystem change nobody asked for and nobody
	// reviewed.
	StagingDir string
}

// Available reports whether a usable web server was detected.
func (w WebServer) Available() bool { return w.Path != "" && w.StagingDir != "" }

// detectWebServer resolves nginx and the staging directory once, at startup,
// alongside the other capability detection.
//
// Detection at construction rather than per request is the same rule the
// executors already follow: a capability report and an operation refusal must
// read the same field, or the node can advertise a capability it will then
// refuse.
func detectWebServer(override, stagingOverride string) WebServer {
	staging := stagingOverride
	if staging == "" {
		staging = defaultStagingDir
	}
	path := override
	if path == "" {
		var found bool
		path, found = resolveProgram(nginxBinaryCandidates...)
		if !found {
			return WebServer{}
		}
	}
	// The staging directory must already exist. Refusing when it is absent is
	// what keeps this operation free of filesystem side effects: provisioning
	// the directory is an installation step, and an operation that created it on
	// demand would be creating a path in a tree it was only granted write access
	// to for the files INSIDE it.
	info, err := os.Stat(staging)
	if err != nil || !info.IsDir() {
		// The binary was found but there is nowhere to stage a candidate.
		// Returning the path is what lets a caller say WHICH half is missing:
		// discarding it here would collapse "no web server" and "no staging
		// directory" into one indistinguishable report, and they have different
		// remedies. Available() still requires both, so nothing can act on this.
		return WebServer{Path: path}
	}
	return WebServer{Path: path, Version: nginxVersion(path), StagingDir: staging}
}

// nginxVersion asks the binary for its version, best-effort.
//
// A version that cannot be read is reported as empty rather than as a guess: the
// reply carries a ToolVersion field that the controller may display, and an
// invented version on an operator's screen is worse than a blank one.
func nginxVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runCommand(ctx, CommandSpec{Path: path, Args: []string{"-v"}})
	if err != nil {
		return ""
	}
	// nginx writes its version to stderr, which runCommand folds into the
	// captured output. The line is conventionally
	// "nginx version: nginx/1.24.0 (Ubuntu)".
	text := out.Stdout + out.Stderr
	if i := strings.Index(text, "nginx/"); i >= 0 {
		rest := text[i+len("nginx/"):]
		if end := strings.IndexAny(rest, " \r\n\t("); end >= 0 {
			return rest[:end]
		}
		return strings.TrimSpace(rest)
	}
	return ""
}

// ValidateWebConfig stages a candidate and asks the web server whether it is
// valid.
//
// The order below is the whole point of the operation and is not rearrangeable:
//
//  1. validate the payload, so garbage is refused before a file exists;
//  2. resolve the staging path through confinement, so a path outside the
//     declared write scope is refused before a file exists;
//  3. write the candidate atomically;
//  4. run `nginx -t -c <candidate>` — pointed at the CANDIDATE, never at the live
//     configuration, so a broken candidate is reported broken rather than
//     installed;
//  5. remove the candidate, whatever happened.
//
// Step 5 runs on every path, including the failure paths. A staging directory
// that accumulates rejected candidates would eventually be a directory an
// operator has to clean by hand, and the file contents are caller-supplied text
// that nobody reviewed.
func (e *Executors) ValidateWebConfig(ctx context.Context, in nodewire.WebConfigValidateInput) (nodewire.WebConfigValidateResult, error) {
	var out nodewire.WebConfigValidateResult

	if err := in.Validate(); err != nil {
		return out, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: err.Error(),
		}
	}

	web := e.WebServer()
	if !web.Available() {
		// Unsupported, not failed. The distinction is what tells an operator to
		// install something rather than to debug something.
		reason := "no web server was found on this host"
		if web.Path != "" {
			reason = "the staging directory for candidate configurations does not exist on this host"
		}
		return out, &nodewire.Error{
			Code:    nodewire.CodeUnsupportedOperation,
			Message: reason,
		}
	}

	confinement, err := newConfinement([]string{web.StagingDir})
	if err != nil {
		return out, fmt.Errorf("nodeagent: staging confinement: %w", err)
	}
	staged, err := confinement.resolve(filepath.Join(web.StagingDir, in.Filename))
	if err != nil {
		// The caller named a file name that does not land in the staging
		// directory. The reason is not echoed: it would disclose the filesystem
		// layout, and the controller does not need it to act — it needs to know
		// the name is unacceptable, which is what this code says.
		return out, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: "the configuration file name is not acceptable",
		}
	}

	// The candidate is written with 0600: it is caller-supplied text, and until
	// it has been validated there is no reason for any other local account to
	// read it. writeFileAtomic also sets the mode before writing, so the file
	// never exists with a wider mode even momentarily.
	if err := writeFileAtomic(staged, []byte(in.Config), 0o600); err != nil {
		return out, fmt.Errorf("nodeagent: stage candidate: %w", err)
	}
	// Removal is registered the moment the file exists, so no later return can
	// forget it.
	defer func() { _ = os.Remove(staged) }()

	e.spawns.Add(1)
	runCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	// -c points nginx at the candidate as its CONFIGURATION ROOT. -t parses and
	// exits. Nothing is reloaded, no socket is touched, and no running worker is
	// affected: a validation failure here cannot take a site down because
	// nothing that is serving is involved.
	result, runErr := runCommand(runCtx, CommandSpec{
		Path: web.Path,
		Args: []string{"-t", "-c", staged},
	})

	out.Tool = "nginx"
	out.ToolVersion = web.Version
	out.Staged = staged
	out.ObservedAt = e.now().UTC()

	// The output has to be taken from the ERROR for the invalid case, and that is
	// not a stylistic choice. exec.go's finishCommand returns an empty
	// CommandResult on a non-zero exit, and nginx -t exits non-zero precisely
	// when the candidate is INVALID — which is the case whose output an operator
	// most needs. The message survives in ErrCommandFailed.Stderr, bounded to 512
	// bytes by boundForMessage, so the truncation flag is set from that bound as
	// well rather than only from validationOutputLimit below.
	var exitErr *ErrCommandFailed
	switch {
	case errors.Is(runErr, ErrOutputLimit):
		// The child wrote more than exec.go will read. There is no output to
		// report, and saying so is better than implying the verdict was clean.
		out.Truncated = true
	case errors.As(runErr, &exitErr):
		out.Output = exitErr.Stderr
		if len(exitErr.Stderr) >= BoundForMessageLimit {
			out.Truncated = true
		}
	default:
		// Whatever else went wrong, the captured streams may still hold it.
		out.Output = strings.TrimSpace(result.Stdout + result.Stderr)
	}

	if len(out.Output) > validationOutputLimit {
		out.Output = out.Output[:validationOutputLimit]
		out.Truncated = true
	}

	// The exit status IS the verdict. A configuration nginx rejects is a
	// successful validation that reports "invalid" — the operation worked, the
	// candidate did not. Returning an error here would make a broken candidate
	// indistinguishable from a broken agent.
	if errors.Is(runErr, context.DeadlineExceeded) {
		return out, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: "the web server did not finish validating within the time allowed",
		}
	}
	if runErr != nil {
		// A non-zero exit from nginx -t is expected for an invalid candidate and
		// is reported through Valid=false. Any OTHER failure — the binary could
		// not be started — has to be distinguished, or a typo in a path would
		// read as "your configuration is invalid".
		if !errors.As(runErr, &exitErr) {
			return out, fmt.Errorf("nodeagent: run web server validation: %w", runErr)
		}
		out.Valid = false
		return out, nil
	}

	out.Valid = true
	return out, nil
}
