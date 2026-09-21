package nodeagent

// backup.go implements the Phase 6 file backup operations.
//
// file.archive packs reviewed source paths into a tar.gz under the backup
// root; file.restore extracts one back. tar is invoked with an absolute path
// from a fixed candidate list, argv only, no shell. Every path is confined
// with path.Clean (unix semantics regardless of the build host OS) before it
// reaches tar, and a failed archive removes its partial artifact.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// confineBackupPath resolves and validates an archive path against the backup root.
func (e *Executors) confineBackupPath(p string) (string, error) {
	clean := path.Clean(p)
	root := strings.TrimRight(e.backupDir, "/")
	if !strings.HasPrefix(clean, root+"/") && clean != root {
		return "", fmt.Errorf("archive path %q must be inside %s", p, e.backupDir)
	}
	return clean, nil
}

// ArchiveFiles packs the source paths into a tar.gz at the archive path and
// returns its size and SHA-256.
func (e *Executors) ArchiveFiles(ctx context.Context, in nodewire.FileArchiveInput) (nodewire.FileArchiveResult, error) {
	if !supportedOS() {
		return nodewire.FileArchiveResult{}, notAvailable("file archive is supported on Linux only")
	}
	if e.tarPath == "" {
		return nodewire.FileArchiveResult{}, notAvailable("tar is not installed on this node")
	}
	archivePath, err := e.confineBackupPath(in.ArchivePath)
	if err != nil {
		return nodewire.FileArchiveResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}
	if mkErr := os.MkdirAll(path.Dir(archivePath), 0750); mkErr != nil {
		return nodewire.FileArchiveResult{}, fmt.Errorf("archive: create parent dir: %w", mkErr)
	}

	// A partial archive must not be left for the caller to mistake for a
	// finished one.
	var ok bool
	defer func() {
		if !ok {
			_ = os.Remove(archivePath)
		}
	}()

	e.spawns.Add(1)
	if _, runErr := e.cmdRunner(ctx, CommandSpec{
		Path:    e.tarPath,
		Args:    archiveArgs(archivePath, in.SourcePaths),
		Timeout: 30 * 60 * time.Second,
	}); runErr != nil {
		return nodewire.FileArchiveResult{}, wrapArchiveErr(runErr, "tar archive")
	}

	data, err := os.ReadFile(archivePath) //nolint:gosec // G304: path is confined above
	if err != nil {
		return nodewire.FileArchiveResult{}, fmt.Errorf("archive: read result: %w", err)
	}
	sum := sha256.Sum256(data)
	ok = true
	return nodewire.FileArchiveResult{
		ArchivePath: archivePath,
		SizeBytes:   int64(len(data)),
		SHA256:      hex.EncodeToString(sum[:]),
		ObservedAt:  e.now().UTC(),
	}, nil
}

// RestoreFiles extracts an archive into the destination directory and reports
// how many files landed.
func (e *Executors) RestoreFiles(ctx context.Context, in nodewire.FileRestoreInput) (nodewire.FileRestoreResult, error) {
	if !supportedOS() {
		return nodewire.FileRestoreResult{}, notAvailable("file restore is supported on Linux only")
	}
	if e.tarPath == "" {
		return nodewire.FileRestoreResult{}, notAvailable("tar is not installed on this node")
	}
	archivePath, err := e.confineBackupPath(in.ArchivePath)
	if err != nil {
		return nodewire.FileRestoreResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}
	dest := path.Clean(in.DestinationDir)
	if !underSourceRoot(dest) {
		return nodewire.FileRestoreResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: fmt.Sprintf("destination %q is not inside an allowed root", in.DestinationDir),
		}
	}
	if mkErr := os.MkdirAll(dest, 0750); mkErr != nil {
		return nodewire.FileRestoreResult{}, fmt.Errorf("restore: create destination: %w", mkErr)
	}

	e.spawns.Add(1)
	result, runErr := e.cmdRunner(ctx, CommandSpec{
		Path: e.tarPath,
		Args: []string{
			"-xzf", archivePath,
			"-C", dest,
			"--verbose",
		},
		Timeout: 30 * 60 * time.Second,
	})
	if runErr != nil {
		return nodewire.FileRestoreResult{}, wrapArchiveErr(runErr, "tar restore")
	}
	return nodewire.FileRestoreResult{
		OK:             true,
		FilesExtracted: countLines(result.Stdout),
		ObservedAt:     e.now().UTC(),
	}, nil
}

// archiveArgs builds the tar argv. Source paths are already validated against
// the closed root set by the wire payload, so they are passed as argv elements
// and never concatenated into a command string.
func archiveArgs(archivePath string, sources []string) []string {
	args := make([]string, 0, 2+len(sources))
	args = append(args, "-czf", archivePath)
	args = append(args, sources...)
	return args
}

// underSourceRoot reports whether a cleaned absolute path sits inside one of
// the reviewed source roots. The wire validation already enforces this; the
// executor re-checks because validation and execution are independent defenses.
func underSourceRoot(clean string) bool {
	for _, root := range nodewire.AllowedArchiveSourceRoots {
		if strings.HasPrefix(clean, root+"/") || clean == root {
			return true
		}
	}
	return false
}

// countLines counts non-empty lines in tar's verbose listing.
func countLines(out string) int64 {
	var n int64
	scanner := bufio.NewScanner(bytes.NewReader([]byte(out)))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n
}

// wrapArchiveErr maps a failed tar onto a wire error code.
func wrapArchiveErr(err error, what string) error {
	var wireErr *nodewire.Error
	if errors.As(err, &wireErr) {
		return err
	}
	var failed *ErrCommandFailed
	if errors.As(err, &failed) && failed.TimedOut {
		return &nodewire.Error{
			Code:      nodewire.CodeDeadlineExceeded,
			Message:   fmt.Sprintf("%s did not finish before its deadline", what),
			Retryable: true,
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return &nodewire.Error{
			Code:      nodewire.CodeDeadlineExceeded,
			Message:   fmt.Sprintf("%s did not complete", what),
			Retryable: true,
		}
	}
	return &nodewire.Error{
		Code:    nodewire.CodeExecutionFailed,
		Message: fmt.Sprintf("%s failed: %v", what, err),
	}
}
