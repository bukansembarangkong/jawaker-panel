// Package targets provides backup destination adapters (BACKUP_RECOVERY.md §3).
//
// Baseline supports local disk and S3-compatible object storage (AWS S3,
// Cloudflare R2, Backblaze B2, MinIO — one API surface). SFTP and remote-server
// adapters are deferred.
//
// No third-party dependencies: S3 signing is implemented with crypto/hmac and
// net/http.
package targets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrUnsupported is returned for a destination type with no adapter.
var ErrUnsupported = errors.New("targets: unsupported destination type")

// Target is one backup destination.
type Target interface {
	// Put stores the object at key. size may be -1 when unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Get retrieves the object. The caller must close the reader.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// Exists reports whether the object is present.
	Exists(ctx context.Context, key string) (bool, error)
	// Delete removes the object. Deleting an absent object is not an error.
	Delete(ctx context.Context, key string) error
}

// Build constructs a Target from a destination type and its config document.
func Build(destType string, configJSON []byte) (Target, error) {
	switch destType {
	case "local":
		var cfg LocalConfig
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &cfg); err != nil {
				return nil, fmt.Errorf("targets: local config: %w", err)
			}
		}
		return NewLocal(cfg)
	case "s3":
		var cfg S3Config
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return nil, fmt.Errorf("targets: s3 config: %w", err)
		}
		return NewS3(cfg)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, destType)
	}
}
