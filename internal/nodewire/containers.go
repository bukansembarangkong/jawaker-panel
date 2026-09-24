package nodewire

import (
	"errors"
	"regexp"
	"time"
)

// containerNameRE matches docker container names that are safe to pass as a CLI
// argument. Docker names are [a-zA-Z0-9][a-zA-Z0-9_.-] with max length 255.
// The pattern is intentionally more restrictive: no leading dash (which would be
// read as a flag), no NUL, no whitespace, no shell metacharacters.
var containerNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,254}$`)

// ValidContainerName reports whether s is safe to pass as a docker container
// name argument. The check is the injection boundary: every value here reaches
// the docker CLI as an argv element.
func ValidContainerName(s string) bool {
	return containerNameRE.MatchString(s)
}

// ContainerListInput is the input for container.list.
type ContainerListInput struct {
	// ProjectID filters to containers whose label jawaker.project matches.
	// Empty means return all JAWAKER-managed containers on this node.
	ProjectID string `json:"project_id,omitempty"`
}

// ContainerListResult is the output of container.list.
type ContainerListResult struct {
	Containers []ContainerSummary `json:"containers"`
	ObservedAt time.Time          `json:"observed_at"`
}

// ContainerSummary is one row in a container.list result.
type ContainerSummary struct {
	// ID is the short container ID (12 hex chars).
	ID string `json:"id"`
	// Name is the container name (unique on the host).
	Name string `json:"name"`
	// Image is the image reference the container was started with.
	Image string `json:"image"`
	// Status is the Docker status string, e.g. "Up 2 hours".
	Status string `json:"status"`
	// State is the Docker state, e.g. "running", "exited", "paused".
	State string `json:"state"`
	// Privileged reports whether the container was started with --privileged.
	// The controller uses this to populate the privileged-container warning.
	Privileged bool `json:"privileged"`
	// Labels are the container's labels. Only jawaker.* prefixed labels are
	// included; others are stripped before the result leaves the agent.
	Labels map[string]string `json:"labels,omitempty"`
	// CreatedAt is the container's creation timestamp.
	CreatedAt time.Time `json:"created_at"`
}

// ContainerInspectInput is the input for container.inspect.
type ContainerInspectInput struct {
	// Name is the container name. It must satisfy ValidContainerName.
	Name string `json:"name"`
}

// Validate checks that the input is well-formed.
func (in ContainerInspectInput) Validate() error {
	if in.Name == "" {
		return errors.New("container name is required")
	}
	if !ValidContainerName(in.Name) {
		return errors.New("container name contains characters that are not safe to pass to the docker CLI")
	}
	return nil
}

// ContainerInspectResult is the output of container.inspect.
type ContainerInspectResult struct {
	// Name is the container name.
	Name string `json:"name"`
	// ID is the full container ID.
	ID string `json:"id"`
	// Image is the full image reference.
	Image string `json:"image"`
	// State is the Docker state object.
	State ContainerState `json:"state"`
	// Privileged reports whether --privileged was set.
	Privileged bool `json:"privileged"`
	// Ports is the port mapping summary.
	Ports []ContainerPort `json:"ports,omitempty"`
	// Labels are the container's labels; only jawaker.* keys are kept.
	Labels map[string]string `json:"labels,omitempty"`
	// ObservedAt is when the snapshot was taken.
	ObservedAt time.Time `json:"observed_at"`
}

// ContainerState is the runtime state of a container.
type ContainerState struct {
	// Status is the high-level status: "running", "exited", "paused", "dead", etc.
	Status string `json:"status"`
	// Running is true when Status == "running".
	Running bool `json:"running"`
	// ExitCode is the last exit code. Meaningful only when Status == "exited".
	ExitCode int `json:"exit_code,omitempty"`
	// StartedAt is the last start time.
	StartedAt time.Time `json:"started_at,omitempty"`
	// FinishedAt is the last stop time.
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// ContainerPort describes one published port.
type ContainerPort struct {
	// HostPort is the port bound on the host.
	HostPort int `json:"host_port"`
	// ContainerPort is the container-side port.
	ContainerPort int `json:"container_port"`
	// Protocol is "tcp" or "udp".
	Protocol string `json:"protocol"`
}

// ContainerLogsInput is the input for container.logs.
type ContainerLogsInput struct {
	// Name is the container name. Must satisfy ValidContainerName.
	Name string `json:"name"`
	// Lines is the maximum number of log lines to return (tail). Max 1000.
	// Zero means the default (200).
	Lines int `json:"lines,omitempty"`
	// RedactPatterns are Go regexp patterns whose matches are replaced with
	// "[REDACTED]" before the log tail leaves the agent. The controller
	// supplies secret values here; the agent never logs these patterns.
	RedactPatterns []string `json:"redact_patterns,omitempty"`
}

// Validate checks that the input is well-formed.
func (in ContainerLogsInput) Validate() error {
	var errs []error
	if in.Name == "" {
		errs = append(errs, errors.New("container name is required"))
	} else if !ValidContainerName(in.Name) {
		errs = append(errs, errors.New("container name contains characters that are not safe to pass to the docker CLI"))
	}
	if in.Lines < 0 {
		errs = append(errs, errors.New("lines must be non-negative"))
	}
	if in.Lines > 1000 {
		errs = append(errs, errors.New("lines exceeds the maximum of 1000"))
	}
	return errors.Join(errs...)
}

// ContainerLogsResult is the output of container.logs.
type ContainerLogsResult struct {
	// Name is the container name.
	Name string `json:"name"`
	// Lines are the log lines, one per element, in chronological order.
	// Secret patterns have been replaced with "[REDACTED]".
	Lines []string `json:"lines"`
	// Truncated reports whether the full log was larger than the requested tail.
	Truncated bool `json:"truncated"`
	// ObservedAt is when the tail was collected.
	ObservedAt time.Time `json:"observed_at"`
}

// ContainerLifecycleInput is the input for container.lifecycle.
type ContainerLifecycleInput struct {
	// Name is the container name. Must satisfy ValidContainerName.
	Name string `json:"name"`
	// Action is one of: "start", "stop", "restart".
	Action string `json:"action"`
}

// Validate checks that the input is well-formed.
func (in ContainerLifecycleInput) Validate() error {
	var errs []error
	if in.Name == "" {
		errs = append(errs, errors.New("container name is required"))
	} else if !ValidContainerName(in.Name) {
		errs = append(errs, errors.New("container name contains characters that are not safe to pass to the docker CLI"))
	}
	switch in.Action {
	case "start", "stop", "restart":
		// valid
	default:
		errs = append(errs, errors.New("action must be one of: start, stop, restart"))
	}
	return errors.Join(errs...)
}

// ContainerLifecycleResult is the output of container.lifecycle.
type ContainerLifecycleResult struct {
	// Name is the container name.
	Name string `json:"name"`
	// Action is the action that was performed.
	Action string `json:"action"`
	// Success reports whether the action completed without error.
	Success bool `json:"success"`
	// Message is an optional detail from docker (trimmed stdout/stderr).
	Message string `json:"message,omitempty"`
}
