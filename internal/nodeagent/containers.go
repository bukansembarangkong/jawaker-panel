package nodeagent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// dockerCandidates is the fixed binary search list for docker. PATH is not
// consulted: resolving via PATH would change the binary if the host's PATH
// changes, which is the same problem as relying on $HOME for a config file.
var dockerCandidates = []string{"/usr/bin/docker", "/usr/local/bin/docker"}

// maxContainerLogLines is the absolute ceiling for container log tails.
// A caller requesting more than this receives the maximum.
const maxContainerLogLines = 1000

// defaultContainerLogLines is returned when the caller requests 0.
const defaultContainerLogLines = 200

// jawakerLabelPrefix is the prefix for labels the agent includes in results.
// Only labels with this prefix are forwarded; all other labels are stripped
// to avoid leaking host-level metadata the controller has no use for.
const jawakerLabelPrefix = "jawaker."

// --- container.list -----------------------------------------------------------

// ListContainers invokes 'docker ps' and returns a summary of containers
// managed by JAWAKER on this node, optionally filtered by project ID.
//
// The output is parsed from 'docker ps --format json'; no shell is involved
// and the container name never reaches a shell interpreter.
func (e *Executors) ListContainers(ctx context.Context, in nodewire.ContainerListInput) (nodewire.ContainerListResult, error) {
	if !supportedOS() {
		return nodewire.ContainerListResult{}, notAvailable("container management is supported on Linux only")
	}
	if e.dockerPath == "" {
		return nodewire.ContainerListResult{}, notAvailable("docker is not installed on this host")
	}

	// --format '{{json .}}' emits one JSON object per line; --no-trunc gives
	// full IDs. The label filter confines output to JAWAKER-managed containers.
	args := []string{"ps", "--no-trunc", "--format", "{{json .}}", "--filter", "label=jawaker.managed=true"}
	if in.ProjectID != "" {
		args = append(args, "--filter", fmt.Sprintf("label=jawaker.project=%s", in.ProjectID))
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.dockerPath,
		Args: args,
	})
	if err != nil {
		return nodewire.ContainerListResult{}, classifyDockerError(err)
	}

	containers, err := parseDockerPSOutput(result.Stdout)
	if err != nil {
		return nodewire.ContainerListResult{}, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: fmt.Sprintf("failed to parse docker ps output: %v", err),
		}
	}

	return nodewire.ContainerListResult{
		Containers: containers,
		ObservedAt: e.now().UTC(),
	}, nil
}

// dockerPSRow is one line of 'docker ps --format {{json .}}' output.
type dockerPSRow struct {
	ID         string `json:"ID"`
	Names      string `json:"Names"`
	Image      string `json:"Image"`
	Status     string `json:"Status"`
	State      string `json:"State"`
	Labels     string `json:"Labels"` // comma-separated k=v pairs
	CreatedAt  string `json:"CreatedAt"`
	RunningFor string `json:"RunningFor"`
}

func parseDockerPSOutput(out string) ([]nodewire.ContainerSummary, error) {
	var containers []nodewire.ContainerSummary
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row dockerPSRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("parse row: %w", err)
		}
		// Truncate ID to 12 chars (short form).
		id := row.ID
		if len(id) > 12 {
			id = id[:12]
		}
		// Name: docker may prefix with "/"; strip it.
		name := strings.TrimPrefix(row.Names, "/")
		labels := parseDockerLabels(row.Labels)
		// Privileged is reported only when docker inspect is run; ps does not
		// expose it. Default false here; inspect provides the authoritative answer.
		containers = append(containers, nodewire.ContainerSummary{
			ID:        id,
			Name:      name,
			Image:     row.Image,
			Status:    row.Status,
			State:     row.State,
			Labels:    filterLabels(labels),
			CreatedAt: time.Time{}, // ps CreatedAt format varies; inspect is authoritative
		})
	}
	return containers, nil
}

// parseDockerLabels splits docker's "k=v,k2=v2" label string into a map.
func parseDockerLabels(raw string) map[string]string {
	labels := make(map[string]string)
	if raw == "" {
		return labels
	}
	for _, pair := range strings.Split(raw, ",") {
		k, v, _ := strings.Cut(pair, "=")
		if k != "" {
			labels[k] = v
		}
	}
	return labels
}

// filterLabels returns only labels whose key starts with jawakerLabelPrefix.
func filterLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range labels {
		if strings.HasPrefix(k, jawakerLabelPrefix) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// --- container.inspect --------------------------------------------------------

// InspectContainer invokes 'docker inspect' for one container by name and
// returns its full state. The name has been validated by the dispatch switch
// before this is called; it is passed as a single argv element.
func (e *Executors) InspectContainer(ctx context.Context, name string) (nodewire.ContainerInspectResult, error) {
	if !supportedOS() {
		return nodewire.ContainerInspectResult{}, notAvailable("container management is supported on Linux only")
	}
	if e.dockerPath == "" {
		return nodewire.ContainerInspectResult{}, notAvailable("docker is not installed on this host")
	}
	if !nodewire.ValidContainerName(name) {
		return nodewire.ContainerInspectResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: "container name contains characters that are not safe to pass to the docker CLI",
		}
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.dockerPath,
		Args: []string{"inspect", "--format", "{{json .}}", "--", name},
	})
	if err != nil {
		return nodewire.ContainerInspectResult{}, classifyDockerError(err)
	}

	return parseDockerInspectOutput(result.Stdout, e.now().UTC())
}

// dockerInspectJSON is the subset of 'docker inspect' JSON we consume.
// Docker returns an array; we take element [0].
type dockerInspectJSON struct {
	ID     string `json:"Id"` // docker's API uses "Id" not "ID"
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged bool `json:"Privileged"`
	} `json:"HostConfig"`
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func parseDockerInspectOutput(out string, now time.Time) (nodewire.ContainerInspectResult, error) {
	out = strings.TrimSpace(out)
	// docker inspect wraps in an array; unwrap.
	if strings.HasPrefix(out, "[") && strings.HasSuffix(out, "]") {
		out = out[1 : len(out)-1]
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nodewire.ContainerInspectResult{}, &nodewire.Error{
			Code:    nodewire.CodeNotFound,
			Message: "container not found",
		}
	}

	var raw dockerInspectJSON
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nodewire.ContainerInspectResult{}, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: fmt.Sprintf("failed to parse docker inspect output: %v", err),
		}
	}

	state := nodewire.ContainerState{
		Status:   raw.State.Status,
		Running:  raw.State.Running,
		ExitCode: raw.State.ExitCode,
	}
	if t, err := time.Parse(time.RFC3339Nano, raw.State.StartedAt); err == nil {
		state.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, raw.State.FinishedAt); err == nil && !t.IsZero() {
		state.FinishedAt = t
	}

	var ports []nodewire.ContainerPort
	for containerPort, bindings := range raw.NetworkSettings.Ports {
		proto := "tcp"
		portNum := 0
		if p, _, found := strings.Cut(containerPort, "/"); found {
			proto = containerPort[len(p)+1:]
			containerPort = p
		}
		if _, err := fmt.Sscanf(containerPort, "%d", &portNum); err != nil {
			continue
		}
		for _, b := range bindings {
			hp := 0
			if _, err := fmt.Sscanf(b.HostPort, "%d", &hp); err != nil {
				continue
			}
			ports = append(ports, nodewire.ContainerPort{
				HostPort:      hp,
				ContainerPort: portNum,
				Protocol:      proto,
			})
		}
	}

	name := strings.TrimPrefix(raw.Name, "/")
	return nodewire.ContainerInspectResult{
		Name:       name,
		ID:         raw.ID,
		Image:      raw.Config.Image,
		State:      state,
		Privileged: raw.HostConfig.Privileged,
		Ports:      ports,
		Labels:     filterLabels(raw.Config.Labels),
		ObservedAt: now,
	}, nil
}

// --- container.logs -----------------------------------------------------------

// ContainerLogs invokes 'docker logs --tail N' for one container and returns
// the last N lines of stdout+stderr with secret patterns redacted.
//
// Redaction happens here, on the agent, because the agent is the only party
// that holds the raw log stream. The controller supplies redact_patterns as
// pre-compiled regexp strings; the agent applies them and never logs them.
func (e *Executors) ContainerLogs(ctx context.Context, in nodewire.ContainerLogsInput) (nodewire.ContainerLogsResult, error) {
	if !supportedOS() {
		return nodewire.ContainerLogsResult{}, notAvailable("container management is supported on Linux only")
	}
	if e.dockerPath == "" {
		return nodewire.ContainerLogsResult{}, notAvailable("docker is not installed on this host")
	}
	if !nodewire.ValidContainerName(in.Name) {
		return nodewire.ContainerLogsResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: "container name contains characters that are not safe to pass to the docker CLI",
		}
	}

	lines := in.Lines
	switch {
	case lines <= 0:
		lines = defaultContainerLogLines
	case lines > maxContainerLogLines:
		lines = maxContainerLogLines
	}

	// Compile redact patterns before spawning the process so a bad regexp is
	// refused with CodeInvalidInput rather than causing a mid-stream failure.
	var redactREs []*regexp.Regexp
	for _, pat := range in.RedactPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nodewire.ContainerLogsResult{}, &nodewire.Error{
				Code:    nodewire.CodeInvalidInput,
				Message: fmt.Sprintf("redact_pattern %q does not compile: %v", pat, err),
			}
		}
		redactREs = append(redactREs, re)
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: e.dockerPath,
		Args: []string{"logs", "--tail", fmt.Sprintf("%d", lines), "--timestamps", "--", in.Name},
	})
	if err != nil {
		return nodewire.ContainerLogsResult{}, classifyDockerError(err)
	}

	// docker logs mixes stdout and stderr; both are in result.Stdout after the
	// command runner merges them (stderr → stdout). Split into lines and redact.
	rawLines := strings.Split(strings.TrimRight(result.Stdout, "\n"), "\n")
	out := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		if line == "" {
			continue
		}
		for _, re := range redactREs {
			line = re.ReplaceAllString(line, "[REDACTED]")
		}
		out = append(out, line)
	}

	return nodewire.ContainerLogsResult{
		Name:       in.Name,
		Lines:      out,
		Truncated:  len(out) >= lines,
		ObservedAt: e.now().UTC(),
	}, nil
}

// --- helpers ------------------------------------------------------------------

// classifyDockerError maps a failed docker command onto a wire error code.
func classifyDockerError(err error) error {
	if err == nil {
		return nil
	}
	return classifyCommandError(err, "docker")
}
