package nodeagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

func TestAppDeployServedOnlyWithSystemdAndGit(t *testing.T) {
	withAll := servedOperations(&Executors{
		hasSystemd:   true,
		gitAvailable: true,
	})
	withoutSystemd := servedOperations(&Executors{
		hasSystemd:   false,
		gitAvailable: true,
	})
	withoutGit := servedOperations(&Executors{
		hasSystemd:   true,
		gitAvailable: false,
	})

	if withoutSystemd[nodewire.OpAppDeploy] {
		t.Error("app.deploy is served on a host without systemd")
	}
	if withoutGit[nodewire.OpAppDeploy] {
		t.Error("app.deploy is served on a host without git")
	}
	if supportedOS() && !withAll[nodewire.OpAppDeploy] {
		t.Error("app.deploy is not served on a supported host with systemd and git")
	}
}

func TestDeployAppRefusesInvalidInput(t *testing.T) {
	exec := NewExecutors(ExecutorOptions{
		AgentVersion: "test",
		GitPath:      "/usr/bin/git",
	})
	ctx := context.Background()

	// Empty project slug
	_, err := exec.DeployApp(ctx, nodewire.AppDeployInput{
		App: nodewire.AppSpec{
			ProjectSlug: "",
			AppSlug:     "my-app",
			RuntimeType: "node",
		},
	})
	if err == nil {
		t.Fatal("expected error for empty project slug")
	}

	// Unknown runtime type
	_, err = exec.DeployApp(ctx, nodewire.AppDeployInput{
		App: nodewire.AppSpec{
			ProjectSlug: "my-proj",
			AppSlug:     "my-app",
			RuntimeType: "ruby", // not in allowlist
		},
		Git: nodewire.GitSpec{
			RepoURL:   "git@example.com:repo.git",
			CommitSHA: "abc1234",
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown runtime type")
	}

	// Port out of range
	badPort := 80 // < 1024
	_, err = exec.DeployApp(ctx, nodewire.AppDeployInput{
		App: nodewire.AppSpec{
			ProjectSlug: "my-proj",
			AppSlug:     "my-app",
			RuntimeType: "node",
			Port:        &badPort,
		},
		Git: nodewire.GitSpec{
			RepoURL:   "git@example.com:repo.git",
			CommitSHA: "abc1234",
		},
	})
	if err == nil {
		t.Fatal("expected error for port < 1024")
	}

	// Malformed commit SHA (not hex)
	_, err = exec.DeployApp(ctx, nodewire.AppDeployInput{
		App: nodewire.AppSpec{
			ProjectSlug: "my-proj",
			AppSlug:     "my-app",
			RuntimeType: "node",
		},
		Git: nodewire.GitSpec{
			RepoURL:   "git@example.com:repo.git",
			CommitSHA: "not-a-hex-sha!",
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid commit sha")
	}
}

func TestDeployAppRefusesUnallowedProgram(t *testing.T) {
	// Program not in allowlist: bash, sh, rm, curl, etc.
	for _, prog := range []string{"bash", "sh", "python2", "ruby", "rm", "sudo"} {
		t.Run(prog, func(t *testing.T) {
			err := validateRuntimePrograms("node", prog, "node")
			if err == nil {
				t.Fatalf("expected program %q to be refused for node runtime", prog)
			}
		})
	}

	// Allowed programs
	for _, prog := range []string{"npm", "npx", "yarn", "pnpm"} {
		t.Run("allowed_"+prog, func(t *testing.T) {
			err := validateRuntimePrograms("node", prog, "node")
			if err != nil {
				t.Fatalf("expected program %q to be allowed for node runtime: %v", prog, err)
			}
		})
	}
	for _, prog := range []string{"python", "python3", "pip", "pip3", "uv"} {
		t.Run("python_"+prog, func(t *testing.T) {
			err := validateRuntimePrograms("python", prog, "python3")
			if err != nil {
				t.Fatalf("expected program %q to be allowed for python runtime: %v", prog, err)
			}
		})
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	app := nodewire.AppSpec{
		ProjectSlug: "proj-1",
		AppSlug:     "web-app",
		RuntimeType: "node",
	}
	content := renderSystemdUnit(app, "/var/www/jawaker/proj-1/web-app/current", "/var/www/jawaker/proj-1/web-app/releases/1/.env", nodewire.CommandSpecWire{
		Program: "node",
		Args:    []string{"server.js", "--port", "3000"},
	})

	for _, want := range []string{
		"Description=Jawaker Application proj-1/web-app",
		"WorkingDirectory=/var/www/jawaker/proj-1/web-app/current",
		"EnvironmentFile=/var/www/jawaker/proj-1/web-app/releases/1/.env",
		"ExecStart=node server.js --port 3000",
		"Restart=on-failure",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("rendered unit missing %q; got:\n%s", want, content)
		}
	}
}

func TestPruneReleases(t *testing.T) {
	tmp := t.TempDir()

	// Create 5 release directories with timestamp prefixes
	dirs := []string{
		"1000-abc1234",
		"2000-def5678",
		"3000-ghi9012",
		"4000-jkl3456",
		"5000-mno7890",
	}
	for _, d := range dirs {
		if err := os.Mkdir(filepath.Join(tmp, d), 0750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	// Prune keeping 3
	pruneReleases(tmp, 3)

	remaining, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(remaining) != 3 {
		t.Fatalf("got %d remaining, want 3", len(remaining))
	}
	// The 3 newest should survive (5000, 4000, 3000)
	survivors := map[string]bool{}
	for _, r := range remaining {
		survivors[r.Name()] = true
	}
	for _, expected := range []string{"5000-mno7890", "4000-jkl3456", "3000-ghi9012"} {
		if !survivors[expected] {
			t.Errorf("expected release %s to survive, but it was deleted", expected)
		}
	}
	for _, deleted := range []string{"1000-abc1234", "2000-def5678"} {
		if survivors[deleted] {
			t.Errorf("expected release %s to be deleted, but it survived", deleted)
		}
	}
}

func TestWriteEnvFile(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, ".env")

	entries := []nodewire.EnvEntryWire{
		{Name: "NODE_ENV", Value: "production"},
		{Name: "PORT", Value: "3000"},
		{Name: "DB_PASS", Value: "s3cr3t!"},
	}
	if err := writeEnvFile(envPath, entries); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}

	raw, err := os.ReadFile(envPath) //nolint:gosec // G304: path is this test's own temp file
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	content := string(raw)
	for _, want := range []string{"NODE_ENV=production", "PORT=3000", "DB_PASS=s3cr3t!"} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q in env file:\n%s", want, content)
		}
	}

	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// On POSIX, file mode should be 0600
	if mode := info.Mode().Perm(); mode&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("env file permissions = %o, want 0600", mode)
	}
}
