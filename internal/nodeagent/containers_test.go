package nodeagent

import (
	"context"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// --- container.list -----------------------------------------------------------

func TestListContainersRejectsNonLinux(t *testing.T) {
	if supportedOS() {
		t.Skip("this test is only relevant on non-Linux builds")
	}
	e := &Executors{dockerPath: "/usr/bin/docker", dockerAvailable: true}
	_, err := e.ListContainers(context.Background(), nodewire.ContainerListInput{})
	if err == nil {
		t.Fatal("expected error on non-Linux, got nil")
	}
}

func TestListContainersRejectsWhenDockerAbsent(t *testing.T) {
	e := &Executors{} // no dockerPath
	_, err := e.ListContainers(context.Background(), nodewire.ContainerListInput{})
	if err == nil {
		t.Fatal("expected error when docker absent, got nil")
	}
	var nwErr *nodewire.Error
	if ok := asError(err, &nwErr); !ok || nwErr.Code != nodewire.CodeNotAvailable {
		t.Errorf("want CodeNotAvailable, got %v", err)
	}
}

func TestListContainersParsesDockerPSOutput(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	// One JAWAKER-managed container in docker ps --format {{json .}} output.
	psLine := `{"ID":"abc123def456","Names":"/my-app","Image":"nginx:1.25","Status":"Up 2 hours","State":"running","Labels":"jawaker.managed=true,jawaker.project=proj1"}`

	e := &Executors{
		dockerPath:      "/usr/bin/docker",
		dockerAvailable: true,
		now: func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
		cmdRunner: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
			// Assert the argv shape.
			if spec.Path != "/usr/bin/docker" {
				t.Errorf("docker path = %q, want /usr/bin/docker", spec.Path)
			}
			if len(spec.Args) == 0 || spec.Args[0] != "ps" {
				t.Errorf("first arg = %q, want ps", spec.Args[0])
			}
			return CommandResult{Stdout: psLine + "\n"}, nil
		},
	}

	result, err := e.ListContainers(context.Background(), nodewire.ContainerListInput{ProjectID: "proj1"})
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(result.Containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(result.Containers))
	}
	c := result.Containers[0]
	if c.Name != "my-app" {
		t.Errorf("name = %q, want my-app", c.Name)
	}
	if c.ID != "abc123def456" {
		t.Errorf("id = %q, want abc123def456", c.ID)
	}
	if c.State != "running" {
		t.Errorf("state = %q, want running", c.State)
	}
	// Only jawaker.* labels should be present.
	for k := range c.Labels {
		if len(k) < len("jawaker.") || k[:8] != "jawaker." {
			t.Errorf("non-jawaker label %q leaked into result", k)
		}
	}
}

// --- container.inspect --------------------------------------------------------

func TestInspectContainerRejectsInvalidName(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	e := &Executors{dockerPath: "/usr/bin/docker", dockerAvailable: true}
	_, err := e.InspectContainer(context.Background(), "bad name with spaces")
	if err == nil {
		t.Fatal("expected error on invalid name, got nil")
	}
}

func TestInspectContainerParsesInspectOutput(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	inspectJSON := `[{"Id":"fullid123","Name":"/my-app","Config":{"Image":"nginx:1.25","Labels":{"jawaker.project":"proj1"}},"HostConfig":{"Privileged":false},"State":{"Status":"running","Running":true,"ExitCode":0,"StartedAt":"2024-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"},"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}}}]`

	e := &Executors{
		dockerPath:      "/usr/bin/docker",
		dockerAvailable: true,
		now: func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
		cmdRunner: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
			if spec.Args[0] != "inspect" {
				t.Errorf("first arg = %q, want inspect", spec.Args[0])
			}
			// Container name must be passed as the last element after "--".
			if spec.Args[len(spec.Args)-1] != "my-app" {
				t.Errorf("last arg = %q, want my-app", spec.Args[len(spec.Args)-1])
			}
			return CommandResult{Stdout: inspectJSON}, nil
		},
	}

	result, err := e.InspectContainer(context.Background(), "my-app")
	if err != nil {
		t.Fatalf("InspectContainer: %v", err)
	}
	if result.Name != "my-app" {
		t.Errorf("name = %q, want my-app", result.Name)
	}
	if !result.State.Running {
		t.Error("expected running=true")
	}
	if result.Privileged {
		t.Error("expected privileged=false")
	}
	if len(result.Ports) != 1 || result.Ports[0].HostPort != 8080 {
		t.Errorf("ports = %v, want [{HostPort:8080 ...}]", result.Ports)
	}
}

// --- container.logs -----------------------------------------------------------

func TestContainerLogsRejectsInvalidName(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	e := &Executors{dockerPath: "/usr/bin/docker", dockerAvailable: true}
	in := nodewire.ContainerLogsInput{Name: "../../etc/passwd"}
	_, err := e.ContainerLogs(context.Background(), in)
	if err == nil {
		t.Fatal("expected error on invalid name, got nil")
	}
}

func TestContainerLogsRedactsSecretPatterns(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	rawOutput := "2024-01-01T00:00:00Z stdout: DB_PASSWORD=supersecret123 connected\n" +
		"2024-01-01T00:00:01Z stdout: normal line\n"

	e := &Executors{
		dockerPath:      "/usr/bin/docker",
		dockerAvailable: true,
		now: func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
		cmdRunner: func(_ context.Context, _ CommandSpec) (CommandResult, error) {
			return CommandResult{Stdout: rawOutput}, nil
		},
	}

	result, err := e.ContainerLogs(context.Background(), nodewire.ContainerLogsInput{
		Name:           "my-app",
		Lines:          10,
		RedactPatterns: []string{`supersecret\d+`},
	})
	if err != nil {
		t.Fatalf("ContainerLogs: %v", err)
	}
	for _, line := range result.Lines {
		if contains(line, "supersecret123") {
			t.Errorf("secret not redacted in line: %q", line)
		}
		if !contains(line, "[REDACTED]") && contains(line, "supersecret") {
			t.Errorf("secret pattern matched but not replaced in line: %q", line)
		}
	}
}

func TestContainerLogsRejectsInvalidRedactPattern(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	e := &Executors{
		dockerPath:      "/usr/bin/docker",
		dockerAvailable: true,
		now: func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
		cmdRunner: func(_ context.Context, _ CommandSpec) (CommandResult, error) {
			return CommandResult{Stdout: "line\n"}, nil
		},
	}
	_, err := e.ContainerLogs(context.Background(), nodewire.ContainerLogsInput{
		Name:           "my-app",
		Lines:          10,
		RedactPatterns: []string{`[invalid(`},
	})
	if err == nil {
		t.Fatal("expected error on invalid redact pattern, got nil")
	}
}

func TestContainerLogsCapsLines(t *testing.T) {
	if !supportedOS() {
		t.Skip("container operations require Linux")
	}
	e := &Executors{
		dockerPath:      "/usr/bin/docker",
		dockerAvailable: true,
		now: func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
		cmdRunner: func(_ context.Context, spec CommandSpec) (CommandResult, error) {
			// Verify that the --tail arg is capped at 1000.
			for i, arg := range spec.Args {
				if arg == "--tail" && i+1 < len(spec.Args) {
					if spec.Args[i+1] != "1000" {
						t.Errorf("tail = %q, want 1000", spec.Args[i+1])
					}
				}
			}
			return CommandResult{}, nil
		},
	}
	_, _ = e.ContainerLogs(context.Background(), nodewire.ContainerLogsInput{
		Name:  "my-app",
		Lines: 9999, // should be capped to 1000
	})
}

// --- helpers ------------------------------------------------------------------

// asError type-asserts err to *nodewire.Error.
func asError(err error, target **nodewire.Error) bool {
	if e, ok := err.(*nodewire.Error); ok {
		*target = e
		return true
	}
	return false
}

// contains is strings.Contains without importing strings.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsLoop(s, sub))
}

func containsLoop(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
