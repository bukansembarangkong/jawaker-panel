package nodeagent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Tests for path confinement. Every case here is a bypass that a naive
// strings.HasPrefix check would miss, so the tests are the specification: if one
// of these starts passing, the check has regressed to a prefix test.

// newTestConfinement builds a confinement over a temporary root, and returns the
// root's REAL path (symlinks resolved, because the temp dir on macOS is behind
// /private).
func newTestConfinement(t *testing.T, subdirs ...string) (*confinement, string) {
	t.Helper()
	root := t.TempDir()
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	for _, d := range subdirs {
		if mkErr := os.MkdirAll(filepath.Join(real, d), 0o750); mkErr != nil {
			t.Fatalf("mkdir %s: %v", d, mkErr)
		}
	}
	c, err := newConfinement([]string{real})
	if err != nil {
		t.Fatalf("newConfinement: %v", err)
	}
	return c, real
}

func TestConfinementAllowsAPathInsideTheRoot(t *testing.T) {
	c, root := newTestConfinement(t, "staging")

	got, err := c.resolve(filepath.Join(root, "staging", "site.conf"))
	if err != nil {
		t.Fatalf("resolve inside root: %v", err)
	}
	if got != filepath.Join(root, "staging", "site.conf") {
		t.Errorf("resolved = %q, want the path inside the root", got)
	}
}

// A file that does not exist yet is the NORMAL case for a write: the target of a
// config apply is a new file. Confinement must accept it, which is why it
// resolves the CONTAINING directory rather than the file.
func TestConfinementAllowsANewFile(t *testing.T) {
	c, root := newTestConfinement(t, "staging")

	if _, err := c.resolve(filepath.Join(root, "staging", "does-not-exist-yet.conf")); err != nil {
		t.Errorf("resolve a not-yet-existing file: %v", err)
	}
}

// THE BYPASS THIS FILE EXISTS FOR. A literal .. must not survive into the
// containment test.
func TestConfinementRefusesTraversal(t *testing.T) {
	c, root := newTestConfinement(t, "staging")

	// Raw concatenation, NOT filepath.Join: Join cleans its result, so every ".."
	// would already be resolved before it reached the code under test, and the
	// test would prove nothing. These strings must still contain ".." on the way
	// in.
	//
	// Only paths whose CLEANED form escapes the root are refused. A ".." that
	// stays inside — staging/../x resolves to root/x — is legal and is asserted
	// in TestConfinementAllowsDotDotThatStaysInside. Confinement resolves
	// traversal rather than banning the two characters, which is what lets a
	// legitimate path through while still closing the escape.
	sep := string(filepath.Separator)
	for _, bad := range []string{
		root + sep + "staging" + sep + ".." + sep + ".." + sep + "etc" + sep + "shadow",
		root + sep + ".." + sep + "escaping.conf",
	} {
		if !strings.Contains(bad, "..") {
			t.Fatalf("test case %q lost its traversal; it cannot test anything", bad)
		}
		if _, err := c.resolve(bad); !errors.Is(err, errConfinement) {
			t.Errorf("resolve %q: err = %v, want a confinement refusal", bad, err)
		}
	}
}

// A ".." that resolves to a place INSIDE the root is allowed. Confinement checks
// where a path lands, not whether it contains traversal characters, and this test
// exists so a future edit cannot quietly tighten the check into a blanket ban on
// ".." — which would reject legitimate paths and invite someone to loosen the
// check entirely.
func TestConfinementAllowsDotDotThatStaysInside(t *testing.T) {
	c, root := newTestConfinement(t, "staging", "other")

	sep := string(filepath.Separator)
	// staging/../other/site.conf resolves to root/other/site.conf: inside.
	inside := root + sep + "staging" + sep + ".." + sep + "other" + sep + "site.conf"
	if !strings.Contains(inside, "..") {
		t.Fatalf("test case %q lost its traversal", inside)
	}
	got, err := c.resolve(inside)
	if err != nil {
		t.Fatalf("resolve a traversal that stays inside: %v", err)
	}
	if want := filepath.Join(root, "other", "site.conf"); got != want {
		t.Errorf("resolved = %q, want %q (the canonical destination)", got, want)
	}
}

// The classic prefix bug: a root "/x/y" must not be judged to contain "/x/y-evil".
// A plain HasPrefix without a separator does exactly that.
func TestConfinementRefusesASiblingWithTheRootAsAPrefix(t *testing.T) {
	root := t.TempDir()
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	inside := filepath.Join(real, "jawaker")
	sibling := real + "-evil"
	for _, d := range []string{inside, sibling} {
		if mkErr := os.MkdirAll(d, 0o750); mkErr != nil {
			t.Fatalf("mkdir %s: %v", d, mkErr)
		}
	}
	c, err := newConfinement([]string{inside})
	if err != nil {
		t.Fatalf("newConfinement: %v", err)
	}

	target := filepath.Join(sibling, "escape.conf")
	if _, err := c.resolve(target); !errors.Is(err, errConfinement) {
		t.Errorf("resolve %q: err = %v, want a refusal (the root is only a string prefix of it)", target, err)
	}
}

// A root is a directory; the operation writes a file. Naming the root itself is
// therefore not a legal target, and accepting it would mean the strictness of the
// separator test had been relaxed.
func TestConfinementRefusesTheRootItself(t *testing.T) {
	c, root := newTestConfinement(t)

	if _, err := c.resolve(root); !errors.Is(err, errConfinement) {
		t.Errorf("resolve the root itself: err = %v, want a refusal", err)
	}
	if _, err := c.resolve(root + string(filepath.Separator)); !errors.Is(err, errConfinement) {
		t.Errorf("resolve the root with a separator: err = %v, want a refusal", err)
	}
}

// A relative path would be interpreted against the process working directory,
// which is not what the descriptor named.
func TestConfinementRefusesRelativePaths(t *testing.T) {
	c, _ := newTestConfinement(t, "staging")

	for _, bad := range []string{"staging/site.conf", "./site.conf", "site.conf"} {
		if _, err := c.resolve(bad); !errors.Is(err, errConfinement) {
			t.Errorf("resolve %q: err = %v, want a refusal", bad, err)
		}
	}
}

// A NUL byte truncates the path as seen by the syscall layer, so a path that
// passes a Go-level check can address something else entirely.
func TestConfinementRefusesNULByte(t *testing.T) {
	c, root := newTestConfinement(t, "staging")

	bad := filepath.Join(root, "staging", "ok.conf") + "\x00../../etc/shadow"
	if _, err := c.resolve(bad); !errors.Is(err, errConfinement) {
		t.Errorf("resolve a path with a NUL byte: err = %v, want a refusal", err)
	}
}

// A directory that does not exist is refused rather than created. The agent must
// never materialize a tree as a side effect of a write, or a caller could grow the
// filesystem one config write at a time.
func TestConfinementRefusesAMissingDirectory(t *testing.T) {
	c, root := newTestConfinement(t)

	bad := filepath.Join(root, "not-provisioned", "site.conf")
	if _, err := c.resolve(bad); !errors.Is(err, errConfinement) {
		t.Errorf("resolve into a missing directory: err = %v, want a refusal", err)
	}
	if _, err := os.Stat(filepath.Join(root, "not-provisioned")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the missing directory was created; a refusal must not have side effects")
	}
}

// A SYMLINK ESCAPES EVERY STRING CHECK. If the containing directory is a link out
// of the root, the path text still looks confined while the write lands outside.
// POSIX only: creating symlinks on Windows needs privileges, and the deployment
// target is Linux.
func TestConfinementRefusesASymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on windows")
	}
	c, root := newTestConfinement(t, "staging")

	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// The path TEXT is inside the root; its real destination is not.
	bad := filepath.Join(link, "site.conf")
	if _, err := c.resolve(bad); !errors.Is(err, errConfinement) {
		t.Errorf("resolve through a symlinked directory: err = %v, want a refusal", err)
	}
}

// An existing final component that is a symlink is refused even when it points
// INSIDE the root: the descriptor authorized writing this file, and following a
// link writes a different one that the caller could then read back.
func TestConfinementRefusesASymlinkedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on windows")
	}
	c, root := newTestConfinement(t, "staging")

	real := filepath.Join(root, "staging", "real.conf")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatalf("write real file: %v", err)
	}
	link := filepath.Join(root, "staging", "link.conf")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := c.resolve(link); !errors.Is(err, errConfinement) {
		t.Errorf("resolve a symlinked file: err = %v, want a refusal", err)
	}
}

// A root that cannot be resolved must fail the CONSTRUCTION, so the operation
// refuses everything rather than running with a silently narrower scope.
func TestConfinementRefusesAnUnresolvableRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := newConfinement([]string{missing}); err == nil {
		t.Error("newConfinement accepted a root that does not exist")
	}
}

// Guard rails on what may be declared as a root at all. A wildcard root is the
// unbounded scope the protocol forbids, and a relative root has no meaning.
func TestConfinementRejectsBadRoots(t *testing.T) {
	for _, bad := range []struct {
		name  string
		roots []string
	}{
		{"empty list", nil},
		{"empty string", []string{""}},
		{"relative", []string{"etc/nginx"}},
		{"wildcard", []string{"/etc/nginx/*"}},
		{"question mark", []string{"/etc/nginx?"}},
	} {
		if _, err := newConfinement(bad.roots); err == nil {
			t.Errorf("newConfinement(%s): accepted, want rejection", bad.name)
		}
	}
}

// Several roots are all honored, so an operation may be granted read access to one
// tree and write access to another.
func TestConfinementHonorsEveryRoot(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	r1, err := filepath.EvalSymlinks(first)
	if err != nil {
		t.Fatalf("resolve first: %v", err)
	}
	r2, err := filepath.EvalSymlinks(second)
	if err != nil {
		t.Fatalf("resolve second: %v", err)
	}
	c, err := newConfinement([]string{r1, r2})
	if err != nil {
		t.Fatalf("newConfinement: %v", err)
	}

	for _, root := range []string{r1, r2} {
		if _, err := c.resolve(filepath.Join(root, "x.conf")); err != nil {
			t.Errorf("resolve inside %q: %v", root, err)
		}
	}

	// And a path inside neither is still refused.
	if _, err := c.resolve(filepath.Join(t.TempDir(), "y.conf")); !errors.Is(err, errConfinement) {
		t.Error("resolve outside every root: want a refusal")
	}
}

// The refusal message must NOT distinguish "outside the root" from "that is a
// symlink". Telling a caller which one it was is a probe for whether a path
// exists, and the wire already collapses all of these into one generic error; the
// sentinel is what makes that collapse possible downstream.
func TestConfinementRefusalIsAlwaysTheSentinel(t *testing.T) {
	c, root := newTestConfinement(t, "staging")

	// Raw concatenation for the traversal case: filepath.Join would clean the
	// ".." away and the case would silently test something else.
	sep := string(filepath.Separator)
	cases := []string{
		root + sep + "staging" + sep + ".." + sep + ".." + sep + "escape.conf",
		"relative.conf",
		filepath.Join(root, "missing-dir", "x.conf"),
		root,
		filepath.Join(root, "staging", "ok.conf") + "\x00evil",
	}
	for _, bad := range cases {
		_, err := c.resolve(bad)
		if err == nil {
			t.Errorf("resolve %q: accepted, want a refusal", bad)
			continue
		}
		if !errors.Is(err, errConfinement) {
			t.Errorf("resolve %q: err = %v, want the confinement sentinel", bad, err)
		}
		// The sentinel must be the wrapping error, so a caller can branch on it
		// without matching message text.
		if !strings.Contains(err.Error(), errConfinement.Error()) {
			t.Errorf("resolve %q: error %q does not carry the sentinel text", bad, err.Error())
		}
	}
}
