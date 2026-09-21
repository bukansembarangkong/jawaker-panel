package nodewire

// backup.go carries the Phase 6 file backup payloads: file.archive packs
// reviewed source paths into a tar.gz under the backup root, file.restore
// extracts one back. Both are confined — an archive cannot be written outside
// the backup root, sources cannot be arbitrary host paths, and a restore
// destination cannot escape the reviewed roots.

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// BackupArchiveRoot is the path-confinement root for file backup archives.
// Distinct from DatabaseDumpRoot: dumps are engine artifacts with their own
// retention, archives are file backups.
const BackupArchiveRoot = "/var/lib/jawaker/backups"

// AllowedArchiveSourceRoots is the closed set of directories file.archive may
// read from. A source outside these roots is refused at validation, before any
// process starts. ponytail: two roots cover app releases and nginx config —
// the only file trees Phase 6 manages; add a root here, in review, if a later
// phase needs another.
var AllowedArchiveSourceRoots = []string{"/var/www/jawaker", "/etc/nginx/jawaker"}

// MaxArchiveSourcePaths bounds one archive request. A backup plan with more
// source paths than this is a plan bug, not a workload.
const MaxArchiveSourcePaths = 32

// FileArchiveInput is the payload for OpFileArchive.
type FileArchiveInput struct {
	SourcePaths []string `json:"source_paths"`
	ArchivePath string   `json:"archive_path"`
}

// Validate checks FileArchiveInput before execution.
func (in FileArchiveInput) Validate() error {
	var errs []error
	if len(in.SourcePaths) == 0 {
		errs = append(errs, errors.New("source_paths must contain at least one path"))
	}
	if len(in.SourcePaths) > MaxArchiveSourcePaths {
		errs = append(errs, fmt.Errorf("source_paths has %d entries, limit is %d", len(in.SourcePaths), MaxArchiveSourcePaths))
	}
	for _, src := range in.SourcePaths {
		clean := path.Clean(src)
		if !path.IsAbs(src) || clean != src {
			errs = append(errs, fmt.Errorf("source path %q must be absolute and clean", src))
			continue
		}
		if !underAnyRoot(clean, AllowedArchiveSourceRoots) {
			errs = append(errs, fmt.Errorf("source path %q is not inside an allowed root", src))
		}
		if strings.ContainsRune(src, 0) {
			errs = append(errs, errors.New("source path contains a NUL byte"))
		}
	}
	if err := validateArchivePath(in.ArchivePath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// FileArchiveResult is the reply to OpFileArchive.
type FileArchiveResult struct {
	ArchivePath string    `json:"archive_path"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	ObservedAt  time.Time `json:"observed_at"`
}

// FileRestoreInput is the payload for OpFileRestore.
type FileRestoreInput struct {
	ArchivePath    string `json:"archive_path"`
	DestinationDir string `json:"destination_dir"`
}

// Validate checks FileRestoreInput before execution.
func (in FileRestoreInput) Validate() error {
	var errs []error
	if err := validateArchivePath(in.ArchivePath); err != nil {
		errs = append(errs, err)
	}
	clean := path.Clean(in.DestinationDir)
	if !path.IsAbs(in.DestinationDir) || clean != in.DestinationDir {
		errs = append(errs, fmt.Errorf("destination_dir %q must be absolute and clean", in.DestinationDir))
	} else if !underAnyRoot(clean, AllowedArchiveSourceRoots) {
		errs = append(errs, fmt.Errorf("destination_dir %q is not inside an allowed root", in.DestinationDir))
	}
	if strings.ContainsRune(in.DestinationDir, 0) {
		errs = append(errs, errors.New("destination_dir contains a NUL byte"))
	}
	return errors.Join(errs...)
}

// FileRestoreResult is the reply to OpFileRestore.
type FileRestoreResult struct {
	OK             bool      `json:"ok"`
	FilesExtracted int64     `json:"files_extracted"`
	ObservedAt     time.Time `json:"observed_at"`
}

// validateArchivePath confines an archive path strictly inside BackupArchiveRoot.
func validateArchivePath(p string) error {
	if p == "" {
		return errors.New("archive_path is required")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("archive_path contains a NUL byte")
	}
	clean := path.Clean(p)
	if !path.IsAbs(p) || clean != p {
		return fmt.Errorf("archive_path %q must be absolute and clean", p)
	}
	// Strictly inside: the root itself is a directory, not an archive. The
	// clean!=p check above already removed any ".." segment before this
	// prefix test runs.
	if !strings.HasPrefix(clean, BackupArchiveRoot+"/") {
		return fmt.Errorf("archive_path %q must be inside %s", p, BackupArchiveRoot)
	}
	return nil
}

// underAnyRoot reports whether clean (absolute, already cleaned) is inside one
// of roots.
func underAnyRoot(clean string, roots []string) bool {
	for _, root := range roots {
		if strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}
