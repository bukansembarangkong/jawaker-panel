package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// fakeBackupExecutors builds an Executors with tar overridden and a temp
// backup root, mirroring fakeExecutors.
func fakeBackupExecutors(t *testing.T) (*Executors, *[]CommandSpec) {
	t.Helper()
	var recorded []CommandSpec
	backupDir := t.TempDir()

	e := NewExecutors(ExecutorOptions{
		AgentVersion: "backup-test",
		BackupDir:    backupDir,
		TarPath:      "/usr/bin/tar",
		Now:          func() time.Time { return time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC) },
	})
	e.tarPath = "/usr/bin/tar"
	e.cmdRunner = func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		recorded = append(recorded, spec)
		// Simulate tar producing the archive so the sha256/size step works.
		if len(spec.Args) > 2 && spec.Args[0] == "-czf" {
			_ = os.WriteFile(spec.Args[1], []byte("fake-archive"), 0600)
		}
		return CommandResult{Stdout: "a\nb\n", ExitCode: 0}, nil
	}
	return e, &recorded
}

func TestArchiveFilesLinuxGate(t *testing.T) {
	if supportedOS() {
		t.Skip("skipping non-Linux assertion on Linux")
	}
	e, recorded := fakeBackupExecutors(t)
	_, err := e.ArchiveFiles(context.Background(), nodewire.FileArchiveInput{
		SourcePaths: []string{"/var/www/jawaker/proj/app"},
		ArchivePath: e.backupDir + "/a.tar.gz",
	})
	var nwErr *nodewire.Error
	if !errors.As(err, &nwErr) || nwErr.Code != nodewire.CodeNotAvailable {
		t.Errorf("got %v, want CodeNotAvailable", err)
	}
	if len(*recorded) != 0 {
		t.Fatal("no command may run when gated")
	}
}

func TestArchiveFilesPathConfinement(t *testing.T) {
	e, recorded := fakeBackupExecutors(t)
	// confineBackupPath is OS-agnostic; test it directly.
	for _, bad := range []string{"/etc/passwd", "../../etc/shadow", "/tmp/evil.tar.gz"} {
		if _, err := e.confineBackupPath(bad); err == nil {
			t.Errorf("bad archive path %q accepted", bad)
		}
	}
	good := e.backupDir + "/valid.tar.gz"
	if _, err := e.confineBackupPath(good); err != nil {
		t.Errorf("valid path rejected: %v", err)
	}
	if len(*recorded) != 0 {
		t.Fatal("confinement check must not spawn anything")
	}
}

func TestArchiveFilesSpawnsTarWithSources(t *testing.T) {
	if !supportedOS() {
		t.Skip("requires Linux")
	}
	e, recorded := fakeBackupExecutors(t)
	res, err := e.ArchiveFiles(context.Background(), nodewire.FileArchiveInput{
		SourcePaths: []string{"/var/www/jawaker/proj/app", "/etc/nginx/jawaker/sites-enabled"},
		ArchivePath: e.backupDir + "/plan-1/run-1.tar.gz",
	})
	if err != nil {
		t.Fatalf("ArchiveFiles: %v", err)
	}
	if len(*recorded) != 1 {
		t.Fatalf("want 1 command, got %d", len(*recorded))
	}
	spec := (*recorded)[0]
	if spec.Path != "/usr/bin/tar" {
		t.Errorf("wrong binary %q", spec.Path)
	}
	joined := strings.Join(spec.Args, " ")
	if !strings.Contains(joined, "-czf") || !strings.Contains(joined, "/var/www/jawaker/proj/app") {
		t.Errorf("unexpected argv: %v", spec.Args)
	}
	if res.SizeBytes <= 0 || len(res.SHA256) != 64 {
		t.Errorf("result missing size/sha: %+v", res)
	}
}

func TestRestoreFilesRejectsBadDestination(t *testing.T) {
	if !supportedOS() {
		t.Skip("requires Linux")
	}
	e, recorded := fakeBackupExecutors(t)
	// Create the archive so the confinement check passes.
	arch := filepath.Join(e.backupDir, "a.tar.gz")
	if wErr := os.WriteFile(arch, []byte("x"), 0600); wErr != nil {
		t.Fatalf("write archive: %v", wErr)
	}
	_, err := e.RestoreFiles(context.Background(), nodewire.FileRestoreInput{
		ArchivePath:    arch,
		DestinationDir: "/etc",
	})
	var nwErr *nodewire.Error
	if !errors.As(err, &nwErr) || nwErr.Code != nodewire.CodeInvalidInput {
		t.Errorf("got %v, want CodeInvalidInput", err)
	}
	if len(*recorded) != 0 {
		t.Fatal("no command may run for a refused destination")
	}
}

func TestUnderSourceRoot(t *testing.T) {
	cases := map[string]bool{
		"/var/www/jawaker/proj/app": true,
		"/etc/nginx/jawaker":        true,
		"/etc/nginx":                false,
		"/etc/passwd":               false,
		"/var/www/jawaker-evil":     false,
	}
	for p, want := range cases {
		if got := underSourceRoot(p); got != want {
			t.Errorf("underSourceRoot(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestCountLines(t *testing.T) {
	if got := countLines("a\nb\n\nc"); got != 3 {
		t.Errorf("countLines = %d, want 3", got)
	}
	if got := countLines(""); got != 0 {
		t.Errorf("countLines(\"\") = %d, want 0", got)
	}
}
