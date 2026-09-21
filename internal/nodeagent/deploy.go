package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// Allowed programs per runtime. A program not in this map is refused before any
// process is spawned.
//
// ADR-030: No generic remote shell command API. Privileged actions are typed,
// scoped, validated and audited.
var runtimeAllowlists = map[string][]string{
	"node":   {"node", "npm", "npx", "yarn", "pnpm", "corepack"},
	"bun":    {"bun", "bunx"},
	"python": {"python", "python3", "pip", "pip3", "uv", "gunicorn", "uvicorn"},
	"php":    {"php", "composer"},
	"static": {"node", "npm", "npx", "yarn", "pnpm", "bun", "python3"},
}

// DeployApp executes an application deployment on the node.
//
// Step order is load-bearing:
//
//  1. Validate payload and check host capabilities (OS, systemd, git).
//  2. Confine all paths: release directory, current symlink, systemd unit.
//  3. Fetch the exact Git commit into a new release directory.
//  4. Execute the build step inside the release directory with an allowlisted program.
//     If the build fails, the release directory is deleted and the live application
//     is UNTOUCHED (Phase 4 gate: failed build leaves existing release serving).
//  5. Write the environment file (0600) and generate the systemd service unit.
//  6. Back up any existing systemd unit and switch the atomic symlink (`current`).
//  7. Restart the service via systemctl and verify health (unit active + HTTP probe).
//  8. If health verification fails, the symlink is restored to the previous release
//     and the service is restarted with RolledBack: true.
//  9. On full success, previous releases beyond the retention count (3) are pruned.
func (e *Executors) DeployApp(ctx context.Context, in nodewire.AppDeployInput) (nodewire.AppDeployResult, error) {
	if err := in.Validate(); err != nil {
		return nodewire.AppDeployResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: err.Error(),
		}
	}
	if !supportedOS() {
		return nodewire.AppDeployResult{}, notAvailable("deployments are supported on Linux only")
	}
	if !e.hasSystemd {
		return nodewire.AppDeployResult{}, notAvailable("systemd is not the running init on this host")
	}
	if !e.gitAvailable {
		return nodewire.AppDeployResult{}, notAvailable("git is not installed on this host")
	}

	// Verify build and start programs against the runtime allowlist.
	if err := validateRuntimePrograms(in.App.RuntimeType, in.Build.Program, in.Start.Program); err != nil {
		return nodewire.AppDeployResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: err.Error(),
		}
	}

	// Confinement: resolve roots and ensure paths cannot escape.
	appsRoot := e.appsRootDir
	appDir := filepath.Join(appsRoot, in.App.ProjectSlug, in.App.AppSlug)
	releasesDir := filepath.Join(appDir, "releases")
	currentSymlink := filepath.Join(appDir, "current")

	if err := os.MkdirAll(releasesDir, 0750); err != nil {
		return nodewire.AppDeployResult{}, fmt.Errorf("deploy: create releases dir: %w", err)
	}

	// Unique release directory: <unix-nano>-<short-sha>
	shortSHA := in.Git.CommitSHA
	if len(shortSHA) > 8 {
		shortSHA = shortSHA[:8]
	}
	releaseName := fmt.Sprintf("%d-%s", e.now().UnixNano(), shortSHA)
	releaseDir := filepath.Join(releasesDir, releaseName)
	if err := os.Mkdir(releaseDir, 0750); err != nil {
		return nodewire.AppDeployResult{}, fmt.Errorf("deploy: create release dir: %w", err)
	}

	// Clean up the new release dir on early failure (build failure, fetch failure)
	// so a broken release does not clutter disk.
	var cleanupReleaseDir = true
	defer func() {
		if cleanupReleaseDir {
			_ = os.RemoveAll(releaseDir)
		}
	}()

	// ── Step 1: Git fetch into release directory ──────────────────────────────
	e.spawns.Add(1)
	if err := e.gitFetch(ctx, releaseDir, in.Git); err != nil {
		return nodewire.AppDeployResult{}, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: fmt.Sprintf("git fetch failed: %v", err),
		}
	}

	// ── Step 2: Build ─────────────────────────────────────────────────────────
	var buildOutput string
	var buildTruncated bool
	if in.Build.Program != "" {
		e.spawns.Add(1)
		output, truncated, buildErr := e.runBuild(ctx, releaseDir, in.Build, in.Env)
		buildOutput = output
		buildTruncated = truncated
		if buildErr != nil {
			// Gate 1: failed build leaves existing release serving.
			// releaseDir is cleaned up by the deferred cleanupReleaseDir.
			return nodewire.AppDeployResult{
				Deployed:       false,
				CommitSHA:      in.Git.CommitSHA,
				BuildOutput:    buildOutput,
				BuildTruncated: buildTruncated,
				HealthState:    nodewire.CapabilityDegraded,
				ObservedAt:     e.now().UTC(),
			}, nil
		}
	}

	// ── Step 3: Write .env file ───────────────────────────────────────────────
	envPath := filepath.Join(releaseDir, ".env")
	if err := writeEnvFile(envPath, in.Env); err != nil {
		return nodewire.AppDeployResult{}, fmt.Errorf("deploy: write env file: %w", err)
	}

	// ── Step 4: Write systemd service unit ────────────────────────────────────
	unitName := fmt.Sprintf("jw-%s-%s.service", in.App.ProjectSlug, in.App.AppSlug)
	unitPath := filepath.Join(e.systemdDir, unitName)
	unitBackupPath := unitPath + ".jawaker-bak"

	// Non-static apps run as managed systemd units.
	if in.App.RuntimeType != "static" {
		workDir := releaseDir
		if in.WorkingDir != "" {
			workDir = filepath.Join(releaseDir, filepath.Clean(in.WorkingDir))
		}
		unitContent := renderSystemdUnit(in.App, workDir, envPath, in.Start)

		// Back up existing unit if present.
		if _, err := os.Stat(unitPath); err == nil {
			_ = os.Rename(unitPath, unitBackupPath)
		}
		if err := writeFileAtomic(unitPath, []byte(unitContent), 0644); err != nil {
			// Restore unit backup if present.
			_ = os.Rename(unitBackupPath, unitPath)
			return nodewire.AppDeployResult{}, fmt.Errorf("deploy: write unit file: %w", err)
		}

		// Reload systemd so the new or modified unit is recognized.
		e.spawns.Add(1)
		if _, err := runCommand(ctx, CommandSpec{
			Path: e.systemctlPath,
			Args: []string{"daemon-reload"},
		}); err != nil {
			_ = os.Remove(unitPath)
			_ = os.Rename(unitBackupPath, unitPath)
			return nodewire.AppDeployResult{}, fmt.Errorf("deploy: systemd daemon-reload: %w", err)
		}
	}

	// ── Step 5: Switch atomic symlink ─────────────────────────────────────────
	// Record previous target for rollback.
	var prevTarget string
	if target, err := os.Readlink(currentSymlink); err == nil {
		prevTarget = target
	}

	// Atomic symlink switch: symlink to temp name, then rename over current.
	tmpSymlink := currentSymlink + ".tmp"
	_ = os.Remove(tmpSymlink)
	if err := os.Symlink(releaseDir, tmpSymlink); err != nil {
		return nodewire.AppDeployResult{}, fmt.Errorf("deploy: create symlink: %w", err)
	}
	if err := os.Rename(tmpSymlink, currentSymlink); err != nil {
		_ = os.Remove(tmpSymlink)
		return nodewire.AppDeployResult{}, fmt.Errorf("deploy: switch symlink: %w", err)
	}

	// Release directory must survive from this point forward.
	cleanupReleaseDir = false

	// ── Step 6: Restart & Health Check ────────────────────────────────────────
	if in.App.RuntimeType != "static" {
		e.spawns.Add(1)
		_, restartErr := runCommand(ctx, CommandSpec{
			Path: e.systemctlPath,
			Args: []string{"restart", "--", unitName},
		})

		healthErr := restartErr
		if healthErr == nil {
			healthErr = e.checkAppHealth(ctx, in.App, unitName)
		}

		if healthErr != nil {
			// ROLLBACK: restore symlink to previous release if one existed.
			var rolledBack bool
			var rollbackReason = healthErr.Error()

			if prevTarget != "" {
				_ = os.Remove(tmpSymlink)
				if symErr := os.Symlink(prevTarget, tmpSymlink); symErr == nil {
					if renErr := os.Rename(tmpSymlink, currentSymlink); renErr == nil {
						rolledBack = true
					}
				}
				// Restore old unit if backup existed.
				if _, statErr := os.Stat(unitBackupPath); statErr == nil {
					_ = os.Rename(unitBackupPath, unitPath)
					_, _ = runCommand(ctx, CommandSpec{
						Path: e.systemctlPath,
						Args: []string{"daemon-reload"},
					})
					_, _ = runCommand(ctx, CommandSpec{
						Path: e.systemctlPath,
						Args: []string{"restart", "--", unitName},
					})
				}
			} else {
				// No previous release (first deploy failed health check).
				_ = os.Remove(currentSymlink)
				_, _ = runCommand(ctx, CommandSpec{
					Path: e.systemctlPath,
					Args: []string{"stop", "--", unitName},
				})
			}

			return nodewire.AppDeployResult{
				Deployed:       false,
				CommitSHA:      in.Git.CommitSHA,
				ReleasePath:    releaseDir,
				CurrentPath:    currentSymlink,
				BuildOutput:    buildOutput,
				BuildTruncated: buildTruncated,
				HealthState:    "unhealthy",
				RolledBack:     rolledBack,
				RollbackReason: rollbackReason,
				ObservedAt:     e.now().UTC(),
			}, nil
		}
	}

	// Remove unit backup on full success.
	_ = os.Remove(unitBackupPath)

	// Prune old releases, keeping the 3 most recent.
	pruneReleases(releasesDir, 3)

	return nodewire.AppDeployResult{
		Deployed:       true,
		CommitSHA:      in.Git.CommitSHA,
		ReleasePath:    releaseDir,
		CurrentPath:    currentSymlink,
		BuildOutput:    buildOutput,
		BuildTruncated: buildTruncated,
		HealthState:    "healthy",
		ObservedAt:     e.now().UTC(),
	}, nil
}

// gitFetch clones or fetches a specific commit using the node's git binary.
func (e *Executors) gitFetch(ctx context.Context, destDir string, git nodewire.GitSpec) error {
	var sshKeyFile string
	var extraEnv []string

	if git.CredentialKind == "ssh_key" && git.SSHKeyPEM != "" {
		tmpKey, err := os.CreateTemp("", "jw-deploy-key-*")
		if err != nil {
			return fmt.Errorf("create temp key: %w", err)
		}
		sshKeyFile = tmpKey.Name()
		defer os.Remove(sshKeyFile) //nolint:errcheck

		if _, err := tmpKey.WriteString(git.SSHKeyPEM); err != nil {
			_ = tmpKey.Close()
			return fmt.Errorf("write temp key: %w", err)
		}
		if err := tmpKey.Close(); err != nil {
			return err
		}
		if err := os.Chmod(sshKeyFile, 0600); err != nil {
			return err
		}
		// StrictHostKeyChecking=accept-new records first-seen key, refuses MITM.
		extraEnv = append(extraEnv, fmt.Sprintf(
			"GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=accept-new -o BatchMode=yes",
			sshKeyFile,
		))
	}

	gitCmd := func(args ...string) error {
		spec := CommandSpec{
			Path:    e.gitPath,
			Args:    args,
			Env:     append(controlledEnv(), extraEnv...),
			Timeout: 5 * time.Minute,
		}
		_, err := runCommand(ctx, spec)
		return err
	}

	if err := gitCmd("init", destDir); err != nil {
		return fmt.Errorf("git init: %w", err)
	}
	if err := gitCmd("-C", destDir, "remote", "add", "origin", git.RepoURL); err != nil {
		return fmt.Errorf("git remote add: %w", err)
	}
	if err := gitCmd("-C", destDir, "fetch", "--depth=1", "origin", git.CommitSHA); err != nil {
		return fmt.Errorf("git fetch %s: %w", git.CommitSHA, err)
	}
	if err := gitCmd("-C", destDir, "checkout", "FETCH_HEAD"); err != nil {
		return fmt.Errorf("git checkout: %w", err)
	}
	return nil
}

// runBuild runs the allowlisted build program inside releaseDir.
func (e *Executors) runBuild(ctx context.Context, releaseDir string, cmd nodewire.CommandSpecWire, env []nodewire.EnvEntryWire) (string, bool, error) {
	progPath, found := resolveProgram("/usr/bin/"+cmd.Program, "/usr/local/bin/"+cmd.Program, "/bin/"+cmd.Program)
	if !found {
		return "", false, fmt.Errorf("build program %q not found on host", cmd.Program)
	}

	buildEnv := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + releaseDir,
	}
	for _, ev := range env {
		buildEnv = append(buildEnv, fmt.Sprintf("%s=%s", ev.Name, ev.Value))
	}

	spec := CommandSpec{
		Path:    progPath,
		Args:    cmd.Args,
		Dir:     releaseDir,
		Env:     buildEnv,
		Timeout: 10 * time.Minute,
	}

	result, err := runCommand(ctx, spec)
	if err != nil {
		var output string
		var truncated bool
		var cmdErr *ErrCommandFailed
		if errors.As(err, &cmdErr) {
			// On a non-zero exit finishCommand returns an EMPTY CommandResult;
			// the message survives only in ErrCommandFailed.Stderr, bounded to
			// BoundForMessageLimit. Same shape as webconfig.go's nginx -t path.
			output = cmdErr.Stderr
			truncated = len(output) >= BoundForMessageLimit
		} else {
			output = err.Error()
		}
		return output, truncated, err
	}

	out := result.Stdout
	if out == "" {
		out = result.Stderr
	}
	return out, false, nil
}

// checkAppHealth verifies systemd unit is active and optionally probes HTTP health endpoint.
func (e *Executors) checkAppHealth(ctx context.Context, app nodewire.AppSpec, unitName string) error {
	// 1. Wait up to 5s for unit to reach active state.
	deadline := e.now().Add(5 * time.Second)
	var lastErr error
	for e.now().Before(deadline) {
		res, err := runCommand(ctx, CommandSpec{
			Path: e.systemctlPath,
			Args: []string{"is-active", "--", unitName},
		})
		if err == nil && strings.TrimSpace(res.Stdout) == "active" {
			lastErr = nil
			break
		}
		lastErr = fmt.Errorf("unit %s is not active", unitName)
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}

	// 2. HTTP probe if health_path and port are specified.
	if app.HealthPath != "" && app.Port != nil {
		healthURL := fmt.Sprintf("http://127.0.0.1:%d%s", *app.Port, app.HealthPath)
		probeDeadline := e.now().Add(10 * time.Second)
		client := &http.Client{Timeout: 2 * time.Second}

		var probeErr error
		for e.now().Before(probeDeadline) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					return nil
				}
				probeErr = fmt.Errorf("HTTP probe returned status %d", resp.StatusCode)
			} else {
				probeErr = err
			}
			time.Sleep(1 * time.Second)
		}
		return fmt.Errorf("health probe to %s failed: %w", healthURL, probeErr)
	}

	return nil
}

// validateRuntimePrograms checks that program names belong to the allowlist for that runtime.
func validateRuntimePrograms(runtimeType, buildProg, startProg string) error {
	allowed, ok := runtimeAllowlists[runtimeType]
	if !ok {
		return fmt.Errorf("unknown runtime %q", runtimeType)
	}

	inList := func(prog string) bool {
		for _, a := range allowed {
			if a == prog {
				return true
			}
		}
		return false
	}

	if buildProg != "" && !inList(buildProg) {
		return fmt.Errorf("build program %q is not in the allowlist for runtime %q", buildProg, runtimeType)
	}
	if startProg != "" && !inList(startProg) {
		return fmt.Errorf("start program %q is not in the allowlist for runtime %q", startProg, runtimeType)
	}
	return nil
}

// writeEnvFile writes an environment file with 0600 permissions.
func writeEnvFile(path string, env []nodewire.EnvEntryWire) error {
	lines := make([]string, 0, len(env))
	for _, ev := range env {
		lines = append(lines, fmt.Sprintf("%s=%s", ev.Name, ev.Value))
	}
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0600)
}

// renderSystemdUnit creates the service unit file text.
func renderSystemdUnit(app nodewire.AppSpec, workDir, envPath string, start nodewire.CommandSpecWire) string {
	execStart := start.Program
	if len(start.Args) > 0 {
		execStart += " " + strings.Join(start.Args, " ")
	}

	return fmt.Sprintf(`[Unit]
Description=Jawaker Application %s/%s
After=network.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=%s
ExecStart=%s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, app.ProjectSlug, app.AppSlug, workDir, envPath, execStart)
}

// pruneReleases keeps the N most recent releases in releasesDir, removing older ones.
func pruneReleases(releasesDir string, keep int) {
	entries, err := os.ReadDir(releasesDir)
	if err != nil {
		return
	}
	var dirs []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry)
		}
	}
	if len(dirs) <= keep {
		return
	}
	// Sort by name descending (name starts with unix-nano timestamp)
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].Name() > dirs[j].Name()
	})
	for _, d := range dirs[keep:] {
		_ = os.RemoveAll(filepath.Join(releasesDir, d.Name()))
	}
}
