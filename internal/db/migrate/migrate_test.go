package migrate

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/fstest"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseOrdersNumerically(t *testing.T) {
	migrations, err := Parse(testdataFS(t, "testdata/valid"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(migrations) != 3 {
		t.Fatalf("got %d migrations, want 3", len(migrations))
	}
	want := []int64{1, 2, 10}
	for i, w := range want {
		if migrations[i].Version != w {
			t.Errorf("migrations[%d].Version = %d, want %d", i, migrations[i].Version, w)
		}
	}
}

func TestParseComputesChecksums(t *testing.T) {
	migrations, err := Parse(testdataFS(t, "testdata/valid"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, m := range migrations {
		if len(m.Checksum) != 64 {
			t.Errorf("%s: checksum = %q, want 64 hex chars", m.Name, m.Checksum)
		}
		if len(m.SQL) == 0 {
			t.Errorf("%s: empty SQL body", m.Name)
		}
	}
	// Identical content must produce identical checksums (determinism).
	fsys := fstest.MapFS{
		"0001_a.sql": {Data: []byte("SELECT 1;\n")},
		"0002_b.sql": {Data: []byte("SELECT 1;\n")},
	}
	ms, err := Parse(fsys)
	if err != nil {
		t.Fatalf("Parse mapfs: %v", err)
	}
	if ms[0].Checksum != ms[1].Checksum {
		t.Error("identical SQL produced different checksums")
	}
}

func TestParseRejectsBadNames(t *testing.T) {
	cases := map[string]string{
		"no version prefix":       "create_things.sql",
		"short version":           "01_create_things.sql",
		"uppercase":               "0001_CreateThings.sql",
		"hyphen":                  "0001_create-things.sql",
		"trailing garbage":        "0001_create_things.sql.bak",
		"version not separated":   "0001createthings.sql",
	}
	for label, name := range cases {
		t.Run(label, func(t *testing.T) {
			fsys := fstest.MapFS{name: {Data: []byte("SELECT 1;")}}
			if _, err := Parse(fsys); err == nil {
				t.Errorf("Parse(%q) accepted, want error", name)
			}
		})
	}
}

func TestParseRejectsDuplicateVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_first.sql":  {Data: []byte("SELECT 1;")},
		"0001_second.sql": {Data: []byte("SELECT 2;")},
	}
	_, err := Parse(fsys)
	if err == nil {
		t.Fatal("duplicate versions accepted, want error")
	}
	if !strings.Contains(err.Error(), "duplicate version") {
		t.Errorf("error %q should mention duplicate version", err)
	}
}

func TestParseSkipsNonSQL(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_real.sql": {Data: []byte("SELECT 1;")},
		"README.md":     {Data: []byte("notes")},
		".keep":         {Data: nil},
	}
	ms, err := Parse(fsys)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ms) != 1 {
		t.Errorf("got %d migrations, want 1 (non-SQL skipped)", len(ms))
	}
}

func TestNewRequiresLogger(t *testing.T) {
	if _, err := New(testdataFS(t, "testdata/valid"), nil); err == nil {
		t.Error("New with nil logger should fail")
	}
}

func TestNewSurfacesParseErrors(t *testing.T) {
	fsys := fstest.MapFS{"bad-name.sql": {Data: []byte("SELECT 1;")}}
	if _, err := New(fsys, testLogger()); err == nil {
		t.Error("New should surface Parse errors")
	}
}

func TestUpRejectsNilPool(t *testing.T) {
	m, err := New(testdataFS(t, "testdata/valid"), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.Up(t.Context(), nil); err == nil {
		t.Error("Up with nil pool should fail")
	}
}
