package nodeagent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Path confinement: the code that makes a descriptor's declared scope TRUE.
//
// This file exists because of an asymmetry in the protocol. nodewire.Scope names
// the filesystem paths an operation may touch, and internal/nodewire validates
// that a mutating descriptor declares SOME scope — but nothing in the agent ever
// read FilesystemWrite. That was harmless while every operation was a read of a
// fixed constant path or a systemctl call on a unit name. It stops being harmless
// the moment an operation accepts a path that a caller chose.
//
// A descriptor that declares a write scope nobody enforces is worse than one that
// declares nothing: the declaration is what a reviewer relies on to answer "what
// can this reach?", and an unenforced answer is a false one. SECURITY.md §7 and
// wire.go's own comment on Descriptor both treat scope as a security artifact, so
// this file is where that claim is honored.
//
// The threat is specifically symlink escape. String prefix tests alone do not
// close it: if "/etc/nginx/jawaker/staging" is writable by the node user, an
// attacker who can create a symlink there can point
// "/etc/nginx/jawaker/staging/x.conf" at /etc/shadow, and a naive
// HasPrefix(clean(path), root) check passes on a path whose REAL destination is
// outside the root. So the check is performed on the fully resolved path, and an
// existing final component that is itself a symlink is refused outright.

// errConfinement is the sentinel for "this path is not writable/readable here".
//
// It is deliberately a single error type: the distinction between "outside the
// root" and "that is a symlink" must NOT reach the wire, because telling a caller
// which of the two it was is a probe for whether a path exists. The full reason
// goes to the agent's own log.
var errConfinement = errors.New("nodeagent: path is outside the operation's declared scope")

// confinement is a resolved set of roots an operation may touch.
//
// Built once per operation from the descriptor, not per path, so the roots are
// resolved a single time and every check compares against the same canonical
// values. Resolving roots lazily per call would also be correct but would do the
// same syscalls repeatedly and, more importantly, would let a root move between
// two checks in one operation.
type confinement struct {
	// roots are canonical absolute paths with every symlink resolved and no
	// trailing separator.
	roots []string
}

// newConfinement resolves the declared roots.
//
// A root that cannot be resolved makes the whole confinement refuse everything,
// rather than being dropped from the list. Silently dropping an unresolvable root
// would leave the remaining roots as the only guard, so a misconfigured host — one
// where /etc/nginx does not exist, say — would keep serving writes under whatever
// roots happen to be present. That is a narrower blast radius than intended, which
// is the safe direction, but it is a DIFFERENT scope than the descriptor claims,
// and a security check that quietly changes its own definition is not a check.
func newConfinement(roots []string) (*confinement, error) {
	if len(roots) == 0 {
		return nil, errors.New("nodeagent: confinement requires at least one root")
	}
	c := &confinement{roots: make([]string, 0, len(roots))}
	for _, declared := range roots {
		if declared == "" {
			return nil, errors.New("nodeagent: confinement root is empty")
		}
		// A wildcard root is exactly the unbounded scope the protocol forbids
		// (see the Scope.Services comment and wire_test's registry guards). It
		// cannot mean anything here, so it is rejected rather than expanded.
		if strings.ContainsAny(declared, "*?") {
			return nil, fmt.Errorf("nodeagent: confinement root %q contains a wildcard", declared)
		}
		if !filepath.IsAbs(declared) {
			return nil, fmt.Errorf("nodeagent: confinement root %q is not absolute", declared)
		}
		resolved, err := filepath.EvalSymlinks(filepath.Clean(declared))
		if err != nil {
			return nil, fmt.Errorf("nodeagent: confinement root %q is not usable: %w", declared, err)
		}
		c.roots = append(c.roots, trimSep(resolved))
	}
	return c, nil
}

// resolve proves target lies strictly inside one declared root and returns the
// path to use.
//
// The rules, in order, each closing one specific bypass:
//
//  1. Absolute only. A relative path would be interpreted against the process
//     working directory, which is not what the descriptor named.
//  2. No NUL byte. It would truncate the path as seen by the syscall layer.
//  3. Clean first, so a literal ".." cannot survive into the containment test.
//  4. Resolve the CONTAINING directory's symlinks, then re-attach the base name.
//     Resolving the file itself is not enough and often not possible: the file
//     may not exist yet, which is the normal case for a write, and
//     filepath.EvalSymlinks fails on a missing path. Resolving the parent is what
//     catches a symlinked directory in the middle of the path.
//  5. Refuse when the final component already exists as a symlink. Writing
//     through it would land outside the root while every string check passes.
//  6. Containment is tested against the RESOLVED directory, and must be strict:
//     the target must be inside a root, not equal to one, because a root is a
//     directory and the operation writes a file.
func (c *confinement) resolve(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("%w: path is empty", errConfinement)
	}
	if strings.ContainsRune(target, 0) {
		return "", fmt.Errorf("%w: path contains a NUL byte", errConfinement)
	}
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("%w: %q is not absolute", errConfinement, target)
	}

	clean := filepath.Clean(target)
	dir, base := filepath.Split(clean)
	if base == "" || base == "." || base == ".." {
		// A path ending in a separator names a directory, not a file.
		return "", fmt.Errorf("%w: %q does not name a file", errConfinement, target)
	}
	dir = trimSep(dir)
	if dir == "" {
		dir = string(filepath.Separator)
	}

	// Resolve the containing directory. If it does not exist, that is a refusal:
	// this code never creates directory trees as a side effect of a write, so an
	// operator cannot find a config file silently materialized three levels deep
	// in a path nobody provisioned.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("%w: %q: directory not usable: %v", errConfinement, target, err)
	}
	realDir = trimSep(realDir)

	// An existing final component that is a symlink is refused regardless of
	// where it points. Even a link that stays inside the root is rejected: the
	// descriptor authorized writing THIS file, and following a link would
	// silently write a different one, whose contents a caller could then read
	// back by aiming at the same link.
	if info, err := os.Lstat(filepath.Join(realDir, base)); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %q is a symlink", errConfinement, target)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: %q cannot be inspected: %v", errConfinement, target, err)
	}

	candidate := filepath.Join(realDir, base)
	if !c.contains(candidate) {
		return "", fmt.Errorf("%w: %q resolves to %q", errConfinement, target, candidate)
	}
	return candidate, nil
}

// contains reports whether path is strictly inside one resolved root.
func (c *confinement) contains(path string) bool {
	for _, root := range c.roots {
		// The separator suffix is what makes this strict and prevents the
		// classic prefix bug where /etc/nginx/jawaker would "contain"
		// /etc/nginx/jawaker-evil/x.
		if strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// trimSep removes trailing separators so a root can be compared with a simple
// prefix-plus-separator test. The filesystem root itself keeps its separator, or
// "/" would compare as an empty prefix and match everything.
func trimSep(p string) string {
	if p == string(filepath.Separator) {
		return p
	}
	return strings.TrimRight(p, string(filepath.Separator))
}
