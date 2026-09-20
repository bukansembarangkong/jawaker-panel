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

// Tests for web.config.validate.
//
// The operation runs a real privileged program against caller-supplied text, so
// these tests are about what it is NOT allowed to do as much as about what it
// does. The property under test throughout: validating a candidate must not be
// able to affect a running site, and it must not be able to write outside its
// staging directory.

// fakeNginx writes a shell script that stands in for nginx, so the executor's
// argv construction, exit-code handling and output capture are exercised without
// requiring nginx on the test host. The script's behavior is driven by the file
// names it is asked about.
//
// A shell script is acceptable HERE and nowhere else: it is a test fixture the
// test itself creates, not something a caller can influence.
func fakeNginx(t *testing.T, dir, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake web server is a POSIX shell script")
	}
	path := filepath.Join(dir, "fake-nginx")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil { //nolint:gosec // G306: the fixture must be executable or it cannot stand in for a web server
		t.Fatalf("write fake nginx: %v", err)
	}
	return path
}

// newWebExecutors builds executors backed by a fake web server and a temporary
// staging directory.
func newWebExecutors(t *testing.T, script string) (*Executors, string) {
	t.Helper()
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	bin := fakeNginx(t, dir, script)
	e := NewExecutors(ExecutorOptions{NginxPath: bin, StagingDir: staging})
	if !e.WebServer().Available() {
		t.Fatalf("the fake web server was not detected: %+v", e.WebServer())
	}
	return e, staging
}

func TestValidateWebConfigAcceptsAValidCandidate(t *testing.T) {
	// A web server that always accepts.
	e, staging := newWebExecutors(t, `echo "syntax is ok"; exit 0`)

	out, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config:   "server { listen 80; server_name example.com; }",
		Filename: "site.conf",
	})
	if err != nil {
		t.Fatalf("ValidateWebConfig: %v", err)
	}
	if !out.Valid {
		t.Errorf("Valid = false, want true; output = %q", out.Output)
	}
	if out.Tool != "nginx" {
		t.Errorf("Tool = %q, want %q", out.Tool, "nginx")
	}
	if !strings.Contains(out.Staged, staging) {
		t.Errorf("Staged = %q, want a path under %q", out.Staged, staging)
	}

	// THE STAGED FILE IS GONE, on the success path too.
	assertStagingEmpty(t, staging)
}

func TestValidateWebConfigReportsAnInvalidCandidateWithoutFailing(t *testing.T) {
	// A web server that rejects, as nginx -t does for a bad configuration.
	e, staging := newWebExecutors(t, `echo "nginx: [emerg] unexpected end of file" >&2; exit 1`)

	out, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config:   "server { this is not valid",
		Filename: "site.conf",
	})
	// The operation SUCCEEDED and the candidate did not. Returning an error
	// here would make a broken configuration indistinguishable from a broken
	// agent, and the caller could not tell an operator which had happened.
	if err != nil {
		t.Fatalf("ValidateWebConfig returned an error for an invalid candidate: %v", err)
	}
	if out.Valid {
		t.Error("Valid = true for a candidate the web server rejected")
	}
	if !strings.Contains(out.Output, "unexpected end of file") {
		t.Errorf("Output = %q, want the web server's own message", out.Output)
	}

	assertStagingEmpty(t, staging)
}

// A web server that cannot be started is NOT the same as a candidate that is
// invalid. Collapsing the two would tell an operator their configuration is
// broken when the real problem is that nginx is missing or unrunnable.
func TestValidateWebConfigDistinguishesAMissingBinary(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	// Detected at construction, then removed, so the executor's own start
	// failure path is exercised rather than the detection path.
	bin := fakeNginx(t, dir, `exit 0`)
	e := NewExecutors(ExecutorOptions{NginxPath: bin, StagingDir: staging})
	if err := os.Remove(bin); err != nil {
		t.Fatalf("remove binary: %v", err)
	}

	_, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config:   "server {}",
		Filename: "site.conf",
	})
	if err == nil {
		t.Fatal("ValidateWebConfig accepted a host where the web server cannot be started")
	}
	// It must NOT be reported as an invalid configuration.
	var wireErr *nodewire.Error
	if errors.As(err, &wireErr) && wireErr.Code == nodewire.CodeInvalidInput {
		t.Errorf("a missing binary was reported as invalid input: %v", wireErr)
	}

	assertStagingEmpty(t, staging)
}

// The payload validator refuses everything that could make the staged path
// address something other than one new file in the staging directory.
func TestValidateWebConfigRejectsBadPayloads(t *testing.T) {
	e, _ := newWebExecutors(t, `exit 0`)
	ctx := context.Background()

	cases := []struct {
		name string
		in   nodewire.WebConfigValidateInput
	}{
		{"empty config", nodewire.WebConfigValidateInput{Config: "", Filename: "a.conf"}},
		{"empty filename", nodewire.WebConfigValidateInput{Config: "x", Filename: ""}},
		{"traversal filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "../../etc/passwd"}},
		{"absolute filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "/etc/passwd"}},
		{"separator in filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "sub/a.conf"}},
		{"backslash filename", nodewire.WebConfigValidateInput{Config: "x", Filename: `sub\a.conf`}},
		{"dot filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "."}},
		{"dotdot filename", nodewire.WebConfigValidateInput{Config: "x", Filename: ".."}},
		{"hidden filename", nodewire.WebConfigValidateInput{Config: "x", Filename: ".hidden"}},
		{"newline in filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "a\nb.conf"}},
		{"semicolon in filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "a;b.conf"}},
		{"NUL in filename", nodewire.WebConfigValidateInput{Config: "x", Filename: "a\x00b.conf"}},
		{"NUL in config", nodewire.WebConfigValidateInput{Config: "a\x00b", Filename: "a.conf"}},
		{"oversized config", nodewire.WebConfigValidateInput{
			Config:   strings.Repeat("x", nodewire.MaxWebConfigBytes+1),
			Filename: "a.conf",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.ValidateWebConfig(ctx, tc.in)
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			var wireErr *nodewire.Error
			if !errors.As(err, &wireErr) {
				t.Fatalf("err = %v, want a nodewire.Error", err)
			}
			if wireErr.Code != nodewire.CodeInvalidInput {
				t.Errorf("code = %q, want %q", wireErr.Code, nodewire.CodeInvalidInput)
			}
		})
	}
}

// A host with no web server refuses with UNSUPPORTED rather than failing. The
// distinction is what tells an operator to install something rather than to
// debug something.
func TestValidateWebConfigRefusesWhenNoWebServer(t *testing.T) {
	e := NewExecutors(ExecutorOptions{NginxPath: "", StagingDir: ""})
	if e.WebServer().Available() {
		t.Fatal("a web server was detected on a host that has none configured")
	}

	_, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config: "server {}", Filename: "a.conf",
	})
	var wireErr *nodewire.Error
	if !errors.As(err, &wireErr) {
		t.Fatalf("err = %v, want a nodewire.Error", err)
	}
	if wireErr.Code != nodewire.CodeUnsupportedOperation {
		t.Errorf("code = %q, want %q", wireErr.Code, nodewire.CodeUnsupportedOperation)
	}
}

// The operation asks the web server about the STAGED CANDIDATE, never about the
// live configuration. This test captures the argv the executor builds, because
// that path argument is the difference between "checks a candidate" and "checks
// what is serving right now" — and only the first is safe to call freely.
func TestValidateWebConfigValidatesTheCandidateNotTheLiveConfig(t *testing.T) {
	// The fake echoes its own argv to stdout and accepts. On success the
	// executor captures stdout into the result's Output, so the test reads the
	// argv from there rather than from a file it would then have to open.
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	bin := fakeNginx(t, dir, `echo "$@"; exit 0`)
	e := NewExecutors(ExecutorOptions{NginxPath: bin, StagingDir: staging})

	out, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config: "server {}", Filename: "candidate.conf",
	})
	if err != nil {
		t.Fatalf("ValidateWebConfig: %v", err)
	}

	argv := out.Output
	// -t so nothing is reloaded, -c pointing at the staged file.
	if !strings.Contains(argv, "-t") {
		t.Errorf("argv = %q, want a -t test invocation", argv)
	}
	if !strings.Contains(argv, filepath.Join(staging, "candidate.conf")) {
		t.Errorf("argv = %q, want the staged candidate path", argv)
	}
	// The live configuration path must not appear at all: this operation has no
	// business naming it, and its presence would mean the candidate is not what
	// was checked.
	if strings.Contains(argv, "/etc/nginx/nginx.conf") {
		t.Errorf("argv = %q names the live configuration, which this operation must not touch", argv)
	}
}

// The staged candidate is written with 0600: until it has been validated there
// is no reason another local account should be able to read caller-supplied text.
func TestValidateWebConfigStagesWithRestrictiveMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on windows")
	}
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	// The fake inspects the mode of the file it was handed and echoes it to
	// stdout, which the executor captures into Output on success. $3 is the
	// staged candidate path (argv is [-t, -c, <staged>]).
	bin := fakeNginx(t, dir, `stat -c %a "$3"; exit 0`)
	e := NewExecutors(ExecutorOptions{NginxPath: bin, StagingDir: staging})

	out, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config: "server {}", Filename: "m.conf",
	})
	if err != nil {
		t.Fatalf("ValidateWebConfig: %v", err)
	}

	mode := strings.TrimSpace(out.Output)
	if mode != "600" {
		t.Errorf("staged file mode = %q, want 600", mode)
	}
}

// The staged file is removed on EVERY path. A staging directory that accumulated
// rejected candidates would become a directory an operator has to clean by hand,
// holding text nobody reviewed.
func TestValidateWebConfigAlwaysRemovesTheStagedFile(t *testing.T) {
	scripts := map[string]string{
		"accepted": `exit 0`,
		"rejected": `echo "bad"; exit 1`,
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			e, staging := newWebExecutors(t, script)
			if _, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
				Config: "server {}", Filename: "s.conf",
			}); err != nil {
				t.Fatalf("ValidateWebConfig: %v", err)
			}
			assertStagingEmpty(t, staging)
		})
	}
}

// A candidate that exceeds exec.go's per-stream output cap is reported with a
// truncation flag rather than as a failed validation. A long error message is
// still a verdict, and failing the operation because nginx was verbose would be
// the wrong outcome.
func TestValidateWebConfigFlagsTruncatedOutput(t *testing.T) {
	// A web server that writes far more than the bound and then rejects.
	e, staging := newWebExecutors(t, `i=0; while [ $i -lt 400 ]; do echo "error line $i padding padding padding" >&2; i=$((i+1)); done; exit 1`)

	out, err := e.ValidateWebConfig(context.Background(), nodewire.WebConfigValidateInput{
		Config: "server {}", Filename: "big.conf",
	})
	if err != nil {
		t.Fatalf("ValidateWebConfig: %v", err)
	}
	if out.Valid {
		t.Error("Valid = true for a rejected candidate")
	}
	if !out.Truncated {
		t.Error("Truncated = false, but the output was certainly cut short")
	}
	if out.Output == "" {
		t.Error("Output is empty; a truncated message must still carry what was captured")
	}

	assertStagingEmpty(t, staging)
}

// The capability report must say whether this host can validate a web config, and
// say so honestly. This mirrors the rule the report already follows for systemd:
// advertising a capability the node cannot honor is worse than an honest gap,
// because the controller offers the operator a button that always fails.
func TestWebCapabilityIsReportedHonest(t *testing.T) {
	// A host with a detected web server reports it available, and names the
	// staging directory the operation will use.
	e, staging := newWebExecutors(t, `exit 0`)
	res, err := e.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	var web *nodewire.Capability
	for i := range res.Capabilities {
		if res.Capabilities[i].Kind == "web" {
			web = &res.Capabilities[i]
		}
	}
	if web == nil {
		t.Fatal("the capability report does not mention a web server")
	}
	if web.State != nodewire.CapabilityAvailable {
		t.Errorf("web state = %q, want available on a host with one", web.State)
	}
	if got := web.Detail["staging_dir"]; got != staging {
		t.Errorf("staging_dir = %v, want %q", got, staging)
	}

	// A host with no web server reports it UNSUPPORTED, never available and
	// never absent. Absent would mean the controller could not distinguish "no
	// nginx here" from "this agent build does not know about nginx".
	none := NewExecutors(ExecutorOptions{})
	res2, err := none.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	var web2 *nodewire.Capability
	for i := range res2.Capabilities {
		if res2.Capabilities[i].Kind == "web" {
			web2 = &res2.Capabilities[i]
		}
	}
	if web2 == nil {
		t.Fatal("the capability report omits the web server on a host without one; it must still be named unsupported")
	}
	if web2.State != nodewire.CapabilityUnsupported {
		t.Errorf("web state = %q, want unsupported on a host without one", web2.State)
	}
	if reason, _ := web2.Detail["reason"].(string); reason == "" {
		t.Error("an unsupported web capability must carry a reason")
	}
}

// assertStagingEmpty fails if any candidate file was left behind.
func assertStagingEmpty(t *testing.T, staging string) {
	t.Helper()
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatalf("read staging dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("staging directory still holds %v; every path must clean up", names)
	}
}

// --- web.config.apply tests --------------------------------------------------

func TestApplyWebConfigRejectsBadPayloads(t *testing.T) {
	e := NewExecutors(ExecutorOptions{})
	ctx := context.Background()

	bad := []struct {
		name string
		in   nodewire.WebConfigApplyInput
	}{
		{"empty config", nodewire.WebConfigApplyInput{Filename: "site.conf"}},
		{"empty filename", nodewire.WebConfigApplyInput{Config: "server {}"}},
		{"path traversal in filename", nodewire.WebConfigApplyInput{Config: "server {}", Filename: "../escape.conf"}},
		{"absolute filename", nodewire.WebConfigApplyInput{Config: "server {}", Filename: "/etc/shadow"}},
		{"oversized config", nodewire.WebConfigApplyInput{Config: strings.Repeat("a", nodewire.MaxWebConfigBytes+1), Filename: "site.conf"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.ApplyWebConfig(ctx, tc.in)
			if err == nil {
				t.Fatalf("ApplyWebConfig accepted %s", tc.name)
			}
			var wireErr *nodewire.Error
			if !errors.As(err, &wireErr) || wireErr.Code != nodewire.CodeInvalidInput {
				t.Errorf("got error %v, want nodewire.Error with code %s", err, nodewire.CodeInvalidInput)
			}
		})
	}
}

func TestApplyWebConfigRefusesWhenNotConfigured(t *testing.T) {
	// An executor with no web server or no sites-enabled directory refuses apply.
	e := NewExecutors(ExecutorOptions{})
	_, err := e.ApplyWebConfig(context.Background(), nodewire.WebConfigApplyInput{
		Config:   "server { listen 80; }",
		Filename: "site.conf",
	})
	if err == nil {
		t.Fatal("ApplyWebConfig succeeded with no web server configured")
	}
	var wireErr *nodewire.Error
	if !errors.As(err, &wireErr) || (wireErr.Code != nodewire.CodeUnsupportedOperation && wireErr.Code != nodewire.CodeNotAvailable) {
		t.Errorf("got error %v, want CodeUnsupportedOperation or CodeNotAvailable", err)
	}
}
