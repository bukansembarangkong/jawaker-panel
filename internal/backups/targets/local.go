package targets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LocalConfig configures the local-disk target.
type LocalConfig struct {
	// BaseDir is the directory all keys are confined under. Required.
	BaseDir string `json:"base_dir"`
}

// Local is a path-confined filesystem destination. Keys never escape BaseDir:
// every key is cleaned with unix semantics and prefix-checked before any file
// operation (same confinement pattern as the Phase 5 dump path).
type Local struct {
	baseDir string
}

// NewLocal validates the config and returns a Local target.
func NewLocal(cfg LocalConfig) (*Local, error) {
	if strings.TrimSpace(cfg.BaseDir) == "" {
		return nil, errors.New("targets: local base_dir is required")
	}
	abs, err := filepath.Abs(cfg.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("targets: resolve base_dir: %w", err)
	}
	return &Local{baseDir: abs}, nil
}

// confine maps a key to an absolute path under baseDir or fails.
func (l *Local) confine(key string) (string, error) {
	if key == "" {
		return "", errors.New("targets: key is required")
	}
	// Reject traversal and absolute keys BEFORE cleaning: path.Clean turns
	// "/../outside" into "/outside", which would then pass a prefix check.
	// A ".." segment anywhere in the key is never legitimate for a backup key.
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." || seg == "" && strings.HasPrefix(key, "/") {
			return "", fmt.Errorf("targets: key %q escapes base_dir", key)
		}
	}
	if strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return "", fmt.Errorf("targets: key %q escapes base_dir", key)
	}
	full := filepath.Join(l.baseDir, filepath.FromSlash(key))
	rel, err := filepath.Rel(l.baseDir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("targets: key %q escapes base_dir", key)
	}
	return full, nil
}

// Put writes the object atomically: temp file in the same directory, then rename.
func (l *Local) Put(ctx context.Context, key string, r io.Reader, _ int64) error {
	full, err := l.confine(key)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return fmt.Errorf("targets: mkdir: %w", err)
	}
	tmp, tmpErr := os.CreateTemp(filepath.Dir(full), ".upload-*")
	if tmpErr != nil {
		return fmt.Errorf("targets: create temp: %w", tmpErr)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName) // no-op after a successful rename
	}()
	if _, err = io.Copy(tmp, r); err != nil {
		return fmt.Errorf("targets: write: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("targets: close temp: %w", err)
	}
	if err = os.Rename(tmpName, full); err != nil {
		return fmt.Errorf("targets: rename: %w", err)
	}
	return nil
}

// Get opens the object for reading.
func (l *Local) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	full, err := l.confine(key)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// Path is confined to baseDir by confine() above; traversal keys never reach here.
	f, err := os.Open(full) //nolint:gosec // G304: path confined by confine()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("targets: %w: %s", ErrNotFound, key)
		}
		return nil, fmt.Errorf("targets: open: %w", err)
	}
	return f, nil
}

// ErrNotFound means the object does not exist at the destination.
var ErrNotFound = errors.New("targets: object not found")

// Exists reports whether the object is present.
func (l *Local) Exists(ctx context.Context, key string) (bool, error) {
	full, err := l.confine(key)
	if err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	_, err = os.Stat(full)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("targets: stat: %w", err)
}

// Delete removes the object; an absent object is not an error.
func (l *Local) Delete(ctx context.Context, key string) error {
	full, err := l.confine(key)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.Remove(full); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("targets: remove: %w", err)
	}
	return nil
}
