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

// defaultSitesEnabledDir is where nginx site configs are installed live.
// It matches the descriptor's FilesystemWrite scope for web.config.apply.
const defaultSitesEnabledDir = "/etc/nginx/jawaker/sites-enabled"

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
	// StagingDir is where candidates are staged for validation. It must exist.
	StagingDir string
	// SitesEnabledDir is where nginx site configs are installed live. It must
	// exist for web.config.apply to be served; it is optional for validate.
	SitesEnabledDir string
}

// Available reports whether a usable web server was detected for validation.
func (w WebServer) Available() bool { return w.Path != "" && w.StagingDir != "" }

// CanApply reports whether the web server supports live config apply.
// It requires both validation capability AND the sites-enabled directory.
func (w WebServer) CanApply() bool { return w.Available() && w.SitesEnabledDir != "" }

// detectWebServer resolves nginx and the staging/sites-enabled directories once,
// at startup, alongside the other capability detection.
//
// Detection at construction rather than per request is the same rule the
// executors already follow: a capability report and an operation refusal must
// read the same field, or the node can advertise a capability it will then
// refuse.
func detectWebServer(override, stagingOverride, sitesEnabledOverride string) WebServer {
	staging := stagingOverride
	if staging == "" {
		staging = defaultStagingDir
	}
	sitesEnabled := sitesEnabledOverride
	if sitesEnabled == "" {
		sitesEnabled = defaultSitesEnabledDir
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

	// sites-enabled: optional for validate (which writes staging only), required
	// for apply (which installs the config live). If it is absent CanApply()
	// returns false and web.config.apply is not served, but validate still is.
	var sitesEnabledPath string
	if si, err := os.Stat(sitesEnabled); err == nil && si.IsDir() {
		sitesEnabledPath = sitesEnabled
	}

	return WebServer{
		Path:            path,
		Version:         nginxVersion(path),
		StagingDir:      staging,
		SitesEnabledDir: sitesEnabledPath,
	}
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

// ApplyWebConfig writes a validated candidate to the LIVE site configuration
// path and reloads the web server. The key safety invariant is:
//
//	AN INVALID CANDIDATE CANNOT REPLACE THE ACTIVE KNOWN-GOOD CONFIGURATION.
//
// The six-step order is the enforcement, not documentation:
//
//  1. Validate payload (refused as CodeInvalidInput, no side effect).
//  2. Verify the web server is fully available including sites-enabled.
//  3. Confine and resolve the live path inside sites-enabled.
//  4. Backup any existing file (atomic rename in the same directory).
//  5. Write the candidate (atomic temp-rename).
//  6. Run nginx -t against the FULL config. Failure → restore backup → reload →
//     return RolledBack:true (NOT an error, a verdict like validate).
//  7. Reload nginx on success. Failure → restore backup → return error.
//  8. Remove backup. Return Applied:true.
//
// Each failure path restores the known-good state and says what happened.
func (e *Executors) ApplyWebConfig(ctx context.Context, in nodewire.WebConfigApplyInput) (nodewire.WebConfigApplyResult, error) {
	var out nodewire.WebConfigApplyResult

	// Step 1: validate payload.
	if err := in.Validate(); err != nil {
		return out, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: err.Error(),
		}
	}

	// Step 2: check full apply capability.
	web := e.WebServer()
	if !web.CanApply() {
		reason := "the web server or its sites-enabled directory is not available on this host"
		if web.Path != "" && web.StagingDir == "" {
			reason = "the staging directory is not present; the web server cannot validate configs"
		} else if web.Path != "" && web.SitesEnabledDir == "" {
			reason = "the sites-enabled directory is not provisioned on this host"
		}
		return out, &nodewire.Error{
			Code:    nodewire.CodeUnsupportedOperation,
			Message: reason,
		}
	}
	if !e.hasSystemd || !supportedOS() {
		return out, notAvailable("config apply requires systemd on Linux for the nginx reload")
	}

	// Step 3: confinement.
	conf, err := newConfinement([]string{web.SitesEnabledDir})
	if err != nil {
		return out, fmt.Errorf("nodeagent: apply confinement: %w", err)
	}
	// Unlike validate, the live path is the DESTINATION, not inside staging.
	// We use resolve() which rejects symlinks in the final component — a
	// symlinked config file would silently redirect the write.
	livePath, err := conf.resolve(filepath.Join(web.SitesEnabledDir, in.Filename))
	if err != nil {
		return out, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: "the configuration file name is not acceptable",
		}
	}
	out.LivePath = livePath
	out.Tool = "nginx"
	out.ToolVersion = web.Version
	out.ObservedAt = e.now().UTC()

	// Step 4: backup the existing live file (atomic rename; no-op if absent).
	backupPath := livePath + ".jawaker-bak"
	out.BackupPath = backupPath
	hasBackup := false
	if _, statErr := os.Lstat(livePath); statErr == nil {
		// The file exists. Rename is atomic within one filesystem — no partial
		// writes for the backup itself.
		if renErr := os.Rename(livePath, backupPath); renErr != nil {
			return out, fmt.Errorf("nodeagent: backup live config: %w", renErr)
		}
		hasBackup = true
	}

	// restoreBackup returns the node to its known-good state. It runs on failure
	// paths only, so any error here goes directly to the log via the wrapping
	// error; the caller already knows the apply failed.
	restoreBackup := func() bool {
		if !hasBackup {
			// There was nothing to restore; the live path simply did not exist.
			_ = os.Remove(livePath)
			return true
		}
		if renErr := os.Rename(backupPath, livePath); renErr != nil {
			// The backup restore itself failed. We log it through the returned
			// error; do not panic, as panicking would kill the agent.
			return false
		}
		return true
	}

	// Step 5: write the candidate atomically.
	// 0644 so the nginx worker (group) can read it. The sites-enabled tree is
	// owned by the JAWAKER user; 0644 is consistent with packages that ship
	// their own conf files there.
	if writeErr := writeFileAtomic(livePath, []byte(in.Config), 0o644); writeErr != nil {
		_ = restoreBackup()
		return out, fmt.Errorf("nodeagent: write live config: %w", writeErr)
	}

	// Step 6: nginx -t on the FULL config (not the candidate in isolation).
	// This is what the gate requires: the candidate must be valid in context,
	// not just valid on its own.
	e.spawns.Add(1)
	verifyCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	verifyResult, verifyErr := runCommand(verifyCtx, CommandSpec{
		Path: web.Path,
		Args: []string{"-t"},
	})
	// Capture output for the result, whatever happened.
	var exitErr *ErrCommandFailed
	switch {
	case errors.Is(verifyErr, ErrOutputLimit):
		out.Truncated = true
	case errors.As(verifyErr, &exitErr):
		out.Output = exitErr.Stderr
		if len(exitErr.Stderr) >= BoundForMessageLimit {
			out.Truncated = true
		}
	default:
		out.Output = strings.TrimSpace(verifyResult.Stdout + verifyResult.Stderr)
	}
	if len(out.Output) > validationOutputLimit {
		out.Output = out.Output[:validationOutputLimit]
		out.Truncated = true
	}

	// If -t failed, the full configuration is invalid. Restore and reload.
	// This is the core gate: the invalid candidate never runs.
	if verifyErr != nil && !errors.As(verifyErr, &exitErr) && errors.Is(verifyErr, context.DeadlineExceeded) {
		// Deadline — restore and report.
		_ = restoreBackup()
		e.spawns.Add(1)
		_ = e.reloadNginx(ctx, web.Path)
		return out, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: "the web server did not finish validating within the time allowed",
		}
	}
	if verifyErr != nil {
		// nginx -t rejected the full config; candidate may be individually valid
		// but breaks an include or another site's config. Restore.
		restored := restoreBackup()
		e.spawns.Add(1)
		_ = e.reloadNginx(ctx, web.Path)
		out.RolledBack = restored
		return out, nil // verdict: RolledBack:true, Applied:false
	}

	// Step 7: reload nginx with the new config in place.
	e.spawns.Add(1)
	if reloadErr := e.reloadNginx(ctx, web.Path); reloadErr != nil {
		_ = restoreBackup()
		return out, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: "nginx reload failed; the previous configuration has been restored",
		}
	}

	// Step 8: success. Remove backup.
	if hasBackup {
		_ = os.Remove(backupPath) // best-effort; the file is stale anyway
	}
	out.Applied = true
	out.BackupPath = "" // cleared: no longer relevant, no cleanup needed
	return out, nil
}

// reloadNginx asks the web server to reload its configuration gracefully.
//
// "Reload" is the correct semantic for a config change: worker processes finish
// their current connections before exiting, unlike "restart" which kills them.
// The systemctl binary is assumed to be at e.systemctlPath, which the caller
// checks before calling.
func (e *Executors) reloadNginx(ctx context.Context, nginxBin string) error {
	if !e.hasSystemd {
		// No systemd: try nginx -s reload instead. Less graceful, but better
		// than nothing on a non-systemd host that somehow has nginx.
		_, err := runCommand(ctx, CommandSpec{
			Path: nginxBin,
			Args: []string{"-s", "reload"},
		})
		return err
	}
	_, err := runCommand(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: []string{"reload", "--", "nginx"},
	})
	return err
}
