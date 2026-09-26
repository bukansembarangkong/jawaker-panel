package nodeagent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// siteNodeJSUnitName returns the systemd unit name for a site's Node.js service.
// Convention: jw-<project_slug>-site-<site_slug>.service
func siteNodeJSUnitName(projectSlug, siteSlug string) string {
	return fmt.Sprintf("jw-%s-site-%s.service", projectSlug, siteSlug)
}

// ManageSiteNodeJS implements OpSiteNodeJSManage.
func (e *Executors) ManageSiteNodeJS(ctx context.Context, in nodewire.SiteNodeJSManageInput) (nodewire.SiteNodeJSManageResult, error) {
	if err := in.Validate(); err != nil {
		return nodewire.SiteNodeJSManageResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}
	if !e.hasSystemd {
		return nodewire.SiteNodeJSManageResult{}, notAvailable("systemd is not the running init on this host")
	}
	unitName := siteNodeJSUnitName(in.ProjectSlug, in.SiteSlug)
	switch in.Action {
	case "npm_install":
		return e.siteNodeJSNpmInstall(ctx, in, unitName)
	case "stop":
		return e.siteNodeJSStop(ctx, unitName)
	case "start", "restart":
		return e.siteNodeJSStartOrRestart(ctx, in, unitName)
	default:
		return nodewire.SiteNodeJSManageResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: fmt.Sprintf("unknown action: %s", in.Action),
		}
	}
}

// StatusSiteNodeJS implements OpSiteNodeJSStatus.
func (e *Executors) StatusSiteNodeJS(ctx context.Context, in nodewire.SiteNodeJSStatusInput) (nodewire.SiteNodeJSStatusResult, error) {
	if err := in.Validate(); err != nil {
		return nodewire.SiteNodeJSStatusResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}
	if !e.hasSystemd {
		return nodewire.SiteNodeJSStatusResult{}, notAvailable("systemd is not the running init on this host")
	}
	unitName := siteNodeJSUnitName(in.ProjectSlug, in.SiteSlug)
	return e.siteNodeJSGetStatus(ctx, unitName)
}

// siteNodeJSResolveNodeBin resolves the node binary for the requested version.
// "system" or "" → relies on PATH ("node").
// Version like "18", "20", "22" → tries known nvm/apt paths, falls back to "node".
func siteNodeJSResolveNodeBin(nodeVersion string) string {
	if nodeVersion == "" || nodeVersion == "system" {
		return "node"
	}
	candidates := []string{
		fmt.Sprintf("/usr/local/nvm/versions/node/v%s/bin/node", nodeVersion),
		fmt.Sprintf("/root/.nvm/versions/node/v%s/bin/node", nodeVersion),
		fmt.Sprintf("/usr/bin/node%s", nodeVersion),
	}
	// Try to find the first one that is present.
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Try with a minor-version glob pattern by checking parent dir entries.
	// e.g. /usr/local/nvm/versions/node/v18.x.y/ where only major is known.
	nvmRoots := []string{"/usr/local/nvm/versions/node", "/root/.nvm/versions/node"}
	for _, root := range nvmRoots {
		if entries, err := os.ReadDir(root); err == nil {
			prefix := "v" + nodeVersion + "."
			for _, e := range entries {
				if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
					bin := filepath.Join(root, e.Name(), "bin", "node")
					if _, err := os.Stat(bin); err == nil {
						return bin
					}
				}
			}
		}
	}
	return "node" // fall back to PATH
}

// siteNodeJSWriteUnitFile writes /etc/systemd/system/<unitName>.
func siteNodeJSWriteUnitFile(in nodewire.SiteNodeJSManageInput, unitName, workDir, nodeBin string) error {
	// Build env lines. Always inject PORT.
	envLines := make([]string, 0, len(in.EnvVars)+1)
	if in.Port > 0 {
		envLines = append(envLines, fmt.Sprintf("Environment=\"PORT=%d\"", in.Port))
	}
	for k, v := range in.EnvVars {
		// Escape quotes in values; systemd unit env values are double-quoted.
		safe := strings.ReplaceAll(v, `"`, `\"`)
		envLines = append(envLines, fmt.Sprintf("Environment=\"%s=%s\"", k, safe))
	}
	envBlock := strings.Join(envLines, "\n")

	// ExecStart: "<nodeBin> <startup_file> [start_args...]"
	// nodeBin may be a bare name (e.g. "node") if not resolved to abs path.
	parts := []string{nodeBin}
	if in.StartupFile != "" {
		parts = append(parts, in.StartupFile)
	}
	parts = append(parts, in.StartArgs...)
	execStart := strings.Join(parts, " ")

	content := fmt.Sprintf(`[Unit]
Description=Jawaker Node.js site %s/%s
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=%s
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
%s
ExecStart=%s
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, in.ProjectSlug, in.SiteSlug, workDir, envBlock, execStart)

	unitPath := filepath.Join("/etc/systemd/system", unitName)
	return writeFileAtomic(unitPath, []byte(content), 0644)
}

func (e *Executors) siteNodeJSStartOrRestart(ctx context.Context, in nodewire.SiteNodeJSManageInput, unitName string) (nodewire.SiteNodeJSManageResult, error) {
	// Site app directory.
	appDir := filepath.Join(e.appsRootDir, in.ProjectSlug, in.SiteSlug)
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: create app dir: %w", err)
	}

	workDir := appDir
	if in.AppRoot != "" {
		workDir = filepath.Join(appDir, filepath.Clean(in.AppRoot))
	}

	nodeBin := siteNodeJSResolveNodeBin(in.NodeVersion)

	if err := siteNodeJSWriteUnitFile(in, unitName, workDir, nodeBin); err != nil {
		return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: write unit file: %w", err)
	}

	e.spawns.Add(1)
	if _, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: []string{"daemon-reload"},
	}); err != nil {
		return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: daemon-reload: %w", err)
	}

	e.spawns.Add(1)
	var ctlArgs []string
	if in.Action == "start" {
		ctlArgs = []string{"enable", "--now", "--", unitName}
	} else {
		ctlArgs = []string{"restart", "--", unitName}
	}
	if _, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: ctlArgs,
	}); err != nil {
		return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: %s: %w", in.Action, err)
	}

	status, err := e.siteNodeJSGetStatus(ctx, unitName)
	if err != nil {
		return nodewire.SiteNodeJSManageResult{}, err
	}
	return nodewire.SiteNodeJSManageResult{
		Action:   in.Action,
		UnitName: unitName,
		State:    status.State,
	}, nil
}

func (e *Executors) siteNodeJSStop(ctx context.Context, unitName string) (nodewire.SiteNodeJSManageResult, error) {
	e.spawns.Add(1)
	if _, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: []string{"stop", "--", unitName},
	}); err != nil {
		return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: stop: %w", err)
	}
	status, err := e.siteNodeJSGetStatus(ctx, unitName)
	if err != nil {
		return nodewire.SiteNodeJSManageResult{}, err
	}
	return nodewire.SiteNodeJSManageResult{
		Action:   "stop",
		UnitName: unitName,
		State:    status.State,
	}, nil
}

func (e *Executors) siteNodeJSNpmInstall(ctx context.Context, in nodewire.SiteNodeJSManageInput, unitName string) (nodewire.SiteNodeJSManageResult, error) {
	appDir := filepath.Join(e.appsRootDir, in.ProjectSlug, in.SiteSlug)
	workDir := appDir
	if in.AppRoot != "" {
		workDir = filepath.Join(appDir, filepath.Clean(in.AppRoot))
	}

	// Resolve npm from the same nvm path as node, if a version was given.
	npmBin := "npm"
	if in.NodeVersion != "" && in.NodeVersion != "system" {
		nodeBin := siteNodeJSResolveNodeBin(in.NodeVersion)
		if nodeBin != "node" {
			npmBin = filepath.Join(filepath.Dir(nodeBin), "npm")
			if _, err := os.Stat(npmBin); err != nil {
				npmBin = "npm" // fall back
			}
		}
	}
	npmPath, found := resolveProgram(
		"/usr/local/bin/"+filepath.Base(npmBin),
		"/usr/bin/"+filepath.Base(npmBin),
		"/bin/"+filepath.Base(npmBin),
	)
	if !found {
		// If npmBin is already an absolute path (resolved from nvm), use it directly.
		if filepath.IsAbs(npmBin) {
			npmPath = npmBin
		} else {
			return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: npm not found on host")
		}
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: npmPath,
		Args: []string{"install", "--production"},
		Dir:  workDir,
		Env:  append(controlledEnv(), "HOME="+workDir),
	})
	msg := result.Stdout
	if msg == "" {
		msg = result.Stderr
	}
	if err != nil {
		return nodewire.SiteNodeJSManageResult{}, fmt.Errorf("site nodejs: npm install: %w", err)
	}
	// Truncate message to avoid blowing the wire limit.
	if len(msg) > BoundForMessageLimit {
		msg = msg[:BoundForMessageLimit]
	}
	return nodewire.SiteNodeJSManageResult{
		Action:   "npm_install",
		UnitName: unitName,
		State:    "inactive",
		Message:  msg,
	}, nil
}

// siteNodeJSGetStatus runs systemctl show and parses key=value output.
func (e *Executors) siteNodeJSGetStatus(ctx context.Context, unitName string) (nodewire.SiteNodeJSStatusResult, error) {
	result := nodewire.SiteNodeJSStatusResult{UnitName: unitName}
	out, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: []string{
			"show", "--no-pager", "--", unitName,
			"--property=ActiveState,MainPID,MemoryCurrent,StateChangeTimestamp",
		},
	})
	if err != nil {
		// Unit likely does not exist; return inactive rather than error.
		result.State = "inactive"
		result.Active = false
		return result, nil //nolint:nilerr
	}
	lines := strings.Split(out.Stdout, "\n")
	for _, line := range lines {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			result.State = strings.TrimSpace(v)
			result.Active = result.State == "active"
		case "MainPID":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n != 0 {
				result.MainPID = n
				result.PID = n
			}
		case "MemoryCurrent":
			if strings.TrimSpace(v) != "[not set]" {
				result.MemoryCurrent = strings.TrimSpace(v)
			}
		case "StateChangeTimestamp":
			result.Since = strings.TrimSpace(v)
		}
	}
	if result.State == "" {
		result.State = "inactive"
	}
	return result, nil
}
