package nodewire

import (
	"strings"
	"testing"
)

func validArchiveInput() FileArchiveInput {
	return FileArchiveInput{
		SourcePaths: []string{"/var/www/jawaker/proj/app"},
		ArchivePath: BackupArchiveRoot + "/plan-1/run-1.tar.gz",
	}
}

func TestFileArchiveInputValid(t *testing.T) {
	if err := validArchiveInput().Validate(); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}

func TestFileArchiveInputRejectsBadPaths(t *testing.T) {
	cases := []struct {
		name string
		in   FileArchiveInput
	}{
		{"empty sources", FileArchiveInput{ArchivePath: BackupArchiveRoot + "/a.tar.gz"}},
		{"relative source", FileArchiveInput{SourcePaths: []string{"proj/app"}, ArchivePath: BackupArchiveRoot + "/a.tar.gz"}},
		{"traversal source", FileArchiveInput{SourcePaths: []string{"/var/www/jawaker/../../etc/passwd"}, ArchivePath: BackupArchiveRoot + "/a.tar.gz"}},
		{"source outside roots", FileArchiveInput{SourcePaths: []string{"/etc/passwd"}, ArchivePath: BackupArchiveRoot + "/a.tar.gz"}},
		{"source is a sibling prefix", FileArchiveInput{SourcePaths: []string{"/var/www/jawaker-evil/x"}, ArchivePath: BackupArchiveRoot + "/a.tar.gz"}},
		{"archive outside root", FileArchiveInput{SourcePaths: []string{"/var/www/jawaker/x"}, ArchivePath: "/tmp/a.tar.gz"}},
		{"archive is the root itself", FileArchiveInput{SourcePaths: []string{"/var/www/jawaker/x"}, ArchivePath: BackupArchiveRoot}},
		{"archive traversal", FileArchiveInput{SourcePaths: []string{"/var/www/jawaker/x"}, ArchivePath: BackupArchiveRoot + "/../etc/passwd"}},
		{"nul in source", FileArchiveInput{SourcePaths: []string{"/var/www/jawaker/x\x00y"}, ArchivePath: BackupArchiveRoot + "/a.tar.gz"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.in.Validate(); err == nil {
				t.Errorf("case %q accepted", tc.name)
			}
		})
	}
}

func TestFileArchiveInputSourceCountLimit(t *testing.T) {
	in := validArchiveInput()
	in.SourcePaths = make([]string, MaxArchiveSourcePaths+1)
	for i := range in.SourcePaths {
		in.SourcePaths[i] = "/var/www/jawaker/proj/app"
	}
	err := in.Validate()
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("over-limit sources accepted: %v", err)
	}
}

func TestFileRestoreInputValid(t *testing.T) {
	in := FileRestoreInput{
		ArchivePath:    BackupArchiveRoot + "/plan-1/run-1.tar.gz",
		DestinationDir: "/var/www/jawaker/proj/app",
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}

func TestFileRestoreInputRejectsBadDestination(t *testing.T) {
	cases := []FileRestoreInput{
		{ArchivePath: BackupArchiveRoot + "/a.tar.gz", DestinationDir: "/etc"},
		{ArchivePath: BackupArchiveRoot + "/a.tar.gz", DestinationDir: "/var/www/jawaker-evil/x"},
		{ArchivePath: BackupArchiveRoot + "/a.tar.gz", DestinationDir: "/etc/nginx/jawaker/../../passwd"},
		{ArchivePath: "/tmp/a.tar.gz", DestinationDir: "/var/www/jawaker/x"},
		{ArchivePath: BackupArchiveRoot + "/a.tar.gz", DestinationDir: ""},
	}
	for _, in := range cases {
		if err := in.Validate(); err == nil {
			t.Errorf("input %+v accepted", in)
		}
	}
}

func TestFileArchiveDescriptor(t *testing.T) {
	desc, ok := Lookup(OpFileArchive)
	if !ok {
		t.Fatal("file.archive not registered")
	}
	if desc.Permission != "backup.create" {
		t.Errorf("permission = %q", desc.Permission)
	}
	if !desc.Mutating || desc.Rollback == "" {
		t.Error("mutating operation must declare rollback")
	}
	if !desc.Retry.Idempotent || desc.Retry.MaxAttempts == 0 {
		t.Error("archive must be retryable")
	}
	restore, ok := Lookup(OpFileRestore)
	if !ok {
		t.Fatal("file.restore not registered")
	}
	if restore.Permission != "backup.restore" {
		t.Errorf("restore permission = %q", restore.Permission)
	}
	if restore.Retry.Idempotent {
		t.Error("restore must not be idempotent")
	}
}
