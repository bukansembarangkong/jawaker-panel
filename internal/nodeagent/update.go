package nodeagent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// agentBinaryPath is the canonical install path of the node-agent binary.
// The executor replaces this file atomically. Not configurable: a configurable
// path would let the controller name an arbitrary file to overwrite.
const agentBinaryPath = "/usr/local/bin/jawaker-nodeagent"

// UpdateNodeAgent downloads the artifact from ArtifactURL, verifies its
// SHA-256 checksum, and atomically replaces the running agent binary.
//
// Security invariants:
//   - ArtifactURL must be https://github.com/** (validated in nodewire.Validate).
//   - The downloaded bytes are verified against ExpectedSHA256 before any write.
//   - The replacement is an atomic os.Rename from a temp file in the same dir,
//     so a partial download never corrupts the running binary.
//   - The temp file is created with mode 0755 (executable).
//   - If verification or rename fails, the temp file is removed.
func (e *Executors) UpdateNodeAgent(ctx context.Context, in nodewire.UpdateNodeAgentInput) (*nodewire.UpdateNodeAgentResult, error) {
	if runtime.GOOS != "linux" {
		return nil, &nodewire.Error{
			Code:    nodewire.CodeUnsupportedOperation,
			Message: "update.node.agent is only supported on Linux",
		}
	}

	// Read running version before replacing.
	prevVersion := e.agentVersion

	// Download artifact.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.ArtifactURL, nil)
	if err != nil {
		return nil, fmt.Errorf("update: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: download artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: fmt.Sprintf("update: artifact download returned HTTP %d", resp.StatusCode),
		}
	}

	// Read and verify checksum before touching disk.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 500<<20)) // 500 MiB hard cap
	if err != nil {
		return nil, fmt.Errorf("update: read artifact: %w", err)
	}
	sum := sha256.Sum256(data)
	got := fmt.Sprintf("%x", sum)
	if !strings.EqualFold(got, in.ExpectedSHA256) {
		return nil, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: fmt.Sprintf("update: checksum mismatch: got %s, want %s — artifact rejected", got, in.ExpectedSHA256),
		}
	}

	// Write to a temp file in the same directory, then rename atomically.
	dir := filepath.Dir(agentBinaryPath)
	tmp, err := os.CreateTemp(dir, ".jawaker-nodeagent-update-*") //nolint:gosec // G304: fixed dir, not user input
	if err != nil {
		return nil, fmt.Errorf("update: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Clean up temp file on any error path.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0755); err != nil { //nolint:gosec // G306: executable binary requires 0755
		_ = tmp.Close()
		return nil, fmt.Errorf("update: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("update: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("update: sync temp file: %w", err)
	}
	_ = tmp.Close()

	// Atomic rename: replaces agentBinaryPath in one syscall.
	if err := os.Rename(tmpName, agentBinaryPath); err != nil {
		return nil, fmt.Errorf("update: atomic rename: %w", err)
	}

	return &nodewire.UpdateNodeAgentResult{
		PreviousVersion:  prevVersion,
		InstalledVersion: in.Version,
		BinaryPath:       agentBinaryPath,
		RequestID:        time.Now().Format(time.RFC3339Nano),
	}, nil
}
