package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// Tests for the site.logs.tail executor.
//
// The safety property under test: deriving the log path from slugs must be
// equivalent to path confinement — the path cannot escape the nginx log root
// regardless of what the slugs say, and the slugs themselves are refused unless
// they match the slug alphabet.

func TestSiteLogsTailInputValidateRejectsBlankSlugs(t *testing.T) {
	in := nodewire.SiteLogsTailInput{LogType: "access", Lines: 10}
	if err := in.Validate(); err == nil {
		t.Error("expected error for blank slugs, got nil")
	}
}

func TestSiteLogsTailInputValidateRejectsBadLogType(t *testing.T) {
	in := nodewire.SiteLogsTailInput{
		ProjectSlug: "acme",
		SiteSlug:    "www",
		LogType:     "nginx_error", // not a valid type
	}
	if err := in.Validate(); err == nil {
		t.Error("expected error for unknown log_type, got nil")
	}
}

func TestSiteLogsTailInputValidateRejectsExcessiveLines(t *testing.T) {
	in := nodewire.SiteLogsTailInput{
		ProjectSlug: "acme",
		SiteSlug:    "www",
		LogType:     "access",
		Lines:       nodewire.MaxSiteLogsTailLines + 1,
	}
	if err := in.Validate(); err == nil {
		t.Errorf("expected error for lines > %d, got nil", nodewire.MaxSiteLogsTailLines)
	}
}

func TestSiteLogsTailInputValidateRejectsSlashInSlug(t *testing.T) {
	in := nodewire.SiteLogsTailInput{
		ProjectSlug: "acme/evil",
		SiteSlug:    "www",
		LogType:     "access",
	}
	if err := in.Validate(); err == nil {
		t.Error("expected error for slug with slash, got nil")
	}
}

func TestSiteLogsTailInputValidateAcceptsValidInput(t *testing.T) {
	cases := []nodewire.SiteLogsTailInput{
		{ProjectSlug: "acme", SiteSlug: "www", LogType: "access", Lines: 0},
		{ProjectSlug: "my-project", SiteSlug: "my-site", LogType: "error", Lines: 100},
		{ProjectSlug: "p1", SiteSlug: "s1", LogType: "access", Lines: nodewire.MaxSiteLogsTailLines},
	}
	for _, tc := range cases {
		if err := tc.Validate(); err != nil {
			t.Errorf("Validate(%v) = %v, want nil", tc, err)
		}
	}
}

func TestTailFileReturnsEmptyForMissingFile(t *testing.T) {
	lines, truncated, err := tailFile(context.Background(), "/nonexistent/path/file.log", 10)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
	_ = lines
	_ = truncated
}

func TestTailFileReturnsAllLinesForSmallFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file path semantics differ on Windows")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	lines, truncated, err := tailFile(context.Background(), logPath, 100)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if truncated {
		t.Error("truncated = true, want false for small file")
	}
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3: %v", len(lines), lines)
	}
	if lines[0] != "line1" || lines[2] != "line3" {
		t.Errorf("unexpected content: %v", lines)
	}
}

func TestTailFileCapsAtMaxLines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file path semantics differ on Windows")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")

	// Write more lines than the requested cap.
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString("entry\n")
	}
	if err := os.WriteFile(logPath, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines, truncated, err := tailFile(context.Background(), logPath, 5)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if len(lines) != 5 {
		t.Errorf("got %d lines, want 5", len(lines))
	}
	if !truncated {
		t.Error("truncated = false, want true when file had more lines than cap")
	}
}

func TestSiteLogsRefusesInvalidSlug(t *testing.T) {
	e := NewExecutors(ExecutorOptions{LogDir: t.TempDir()})
	_, err := e.SiteLogs(context.Background(), nodewire.SiteLogsTailInput{
		ProjectSlug: "../etc",
		SiteSlug:    "www",
		LogType:     "access",
	})
	if err == nil {
		t.Error("expected error for path-traversal slug, got nil")
	}
	var wireErr *nodewire.Error
	if !errors.As(err, &wireErr) || wireErr.Code != nodewire.CodeInvalidInput {
		t.Errorf("got %v, want CodeInvalidInput", err)
	}
}

func TestSiteLogsReturnsEmptyForMissingSite(t *testing.T) {
	logDir := t.TempDir()
	e := NewExecutors(ExecutorOptions{LogDir: logDir})
	res, err := e.SiteLogs(context.Background(), nodewire.SiteLogsTailInput{
		ProjectSlug: "acme",
		SiteSlug:    "www",
		LogType:     "access",
	})
	if err != nil {
		t.Fatalf("SiteLogs returned error for missing log file: %v", err)
	}
	if len(res.Lines) != 0 {
		t.Errorf("got %d lines, want 0 for unserved site", len(res.Lines))
	}
}

func TestSiteLogsReadsRealFileInTempDir(t *testing.T) {
	logDir := t.TempDir()
	e := NewExecutors(ExecutorOptions{LogDir: logDir})

	// Canonical file: <project>--<site>-<type>.log
	logFile := filepath.Join(logDir, "acme--store-access.log")
	if err := os.WriteFile(logFile, []byte("127.0.0.1 - GET / HTTP/1.1 200\n127.0.0.1 - GET /about HTTP/1.1 200\n"), 0o600); err != nil {
		t.Fatalf("write fixture log: %v", err)
	}

	res, err := e.SiteLogs(context.Background(), nodewire.SiteLogsTailInput{
		ProjectSlug: "acme",
		SiteSlug:    "store",
		LogType:     "access",
		Lines:       10,
	})
	if err != nil {
		t.Fatalf("SiteLogs: %v", err)
	}
	if len(res.Lines) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(res.Lines), res.Lines)
	}
	if res.Lines[0] != "127.0.0.1 - GET / HTTP/1.1 200" {
		t.Errorf("unexpected first line: %q", res.Lines[0])
	}
}
