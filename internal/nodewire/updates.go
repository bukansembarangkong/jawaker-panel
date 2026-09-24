package nodewire

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
)

// ── update.node.agent ──────────────────────────────────────────────────────────

// UpdateNodeAgentInput is the input for update.node.agent.
// The controller populates ArtifactURL and ExpectedSHA256 from a verified release;
// the agent downloads, verifies, and atomically replaces itself.
type UpdateNodeAgentInput struct {
	// ArtifactURL is the HTTPS URL of the node-agent binary to download.
	// Only github.com release URLs are accepted by the executor.
	ArtifactURL string `json:"artifact_url"`
	// ExpectedSHA256 is the lowercase hex SHA-256 checksum of the binary.
	ExpectedSHA256 string `json:"expected_sha256"`
	// Version is the human-readable version string (for logging only).
	Version string `json:"version"`
}

// Validate checks input.
func (in UpdateNodeAgentInput) Validate() error {
	if in.ArtifactURL == "" {
		return errors.New("artifact_url: required")
	}
	u, err := url.Parse(in.ArtifactURL)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("artifact_url: must be an https:// URL, got %q", in.ArtifactURL)
	}
	if u.Host != "github.com" {
		return fmt.Errorf("artifact_url: host must be github.com, got %q", u.Host)
	}
	if len(in.ExpectedSHA256) != sha256.Size*2 {
		return fmt.Errorf("expected_sha256: must be 64 hex chars, got %d", len(in.ExpectedSHA256))
	}
	return nil
}

// UpdateNodeAgentResult is the output of update.node.agent.
type UpdateNodeAgentResult struct {
	// PreviousVersion is the agent version before the update.
	PreviousVersion string `json:"previous_version"`
	// InstalledVersion is the version now installed (= input.Version).
	InstalledVersion string `json:"installed_version"`
	// BinaryPath is the path of the replaced binary (for audit).
	BinaryPath string `json:"binary_path"`
	// RequestID echoes the call request ID.
	RequestID string `json:"request_id"`
}

// verifyChecksumReader reads from r, computes SHA-256, compares to expected.
// Returns ErrChecksumMismatch if the digest does not match.
var ErrChecksumMismatch = errors.New("update: SHA-256 checksum mismatch — artifact may be tampered")

func verifyChecksumReader(r io.Reader, expectedHex string) ([]byte, error) {
	h := sha256.New()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != expectedHex {
		return nil, fmt.Errorf("%w: got %s, want %s", ErrChecksumMismatch, got, expectedHex)
	}
	return data, nil
}
