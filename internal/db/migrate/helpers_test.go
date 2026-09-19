package migrate

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// testdataFS returns an fs.FS rooted at the given testdata directory.
func testdataFS(t *testing.T, dir string) fs.FS {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("testdata dir %s missing: %v", abs, err)
	}
	return os.DirFS(abs)
}
