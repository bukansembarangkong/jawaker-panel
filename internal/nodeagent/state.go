// Package nodeagent implements the JAWAKER node agent: the daemon that runs on a
// managed server, authenticates the controller, executes typed operations, and
// reports observed state.
//
// # What this package is allowed to be
//
// ARCHITECTURE.md §3.4 makes the agent a security boundary. Two consequences
// shape every file here:
//
//   - It executes ONLY operations from the closed registry in internal/nodewire.
//     There is no code path that turns a string into a command, and no shell is
//     ever invoked. An operation's target is validated against its descriptor's
//     declared scope before anything is started.
//   - It verifies the controller's certificate against a PINNED root and an
//     expected identity. It does not trust an address, and it does not trust a
//     chain that merely verifies against a system store.
//
// # What this package must survive
//
// ARCHITECTURE.md §13: "central controller temporarily unavailable -> existing
// node workloads continue serving traffic." The agent therefore has no
// controller-outage failure mode: losing the controller stops heartbeats, logs
// errors, and does nothing else. It never signals a hosted process, never stops
// a unit, and never exits. Operations are only ever executed in response to a
// request that arrived over an authenticated channel, so with no channel there is
// nothing to execute. That property is asserted by a test rather than assumed.
package nodeagent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// File names within the state directory.
const (
	identityFile     = "node-identity.pem"
	controllerCAFile = "controller-ca.pem"
	configFile       = "agent.json"
	// identityMode is the permission on the node's private key material.
	//
	// 0600 is not a default to be tuned: the file contains the node's private
	// key, which is the sole proof of this node's identity. Anything wider lets
	// another local account impersonate the node to the controller.
	identityMode = 0o600
	// dirMode keeps the state directory itself unreadable by other local users,
	// so the key's 0600 is not undermined by a listable parent.
	dirMode = 0o700
)

// State is the agent's persisted identity and trust configuration, as loaded
// from the state directory.
type State struct {
	// Dir is the state directory this State was loaded from.
	Dir string
	// ServerID is the controller-side identifier for this node.
	ServerID string
	// ControllerAddress is the host:port the controller's node listener (and its
	// enrollment endpoint) is reached at.
	ControllerAddress string
	// ControllerID is the controller identity this node pins. With the root it
	// forms the pair the agent checks on every connection, so a valid certificate
	// from a DIFFERENT controller is refused.
	ControllerID string
	// Identity is this node's certificate and key.
	Identity *pki.Leaf
	// ControllerRootPEM is the pinned controller certificate authority.
	ControllerRootPEM []byte
}

// Config is the non-secret portion of the agent configuration, persisted as JSON
// beside the identity.
//
// It is separate from the identity so that the trust facts an operator may need
// to inspect — which controller, which address — are readable without touching
// key material.
type Config struct {
	ServerID          string `json:"server_id"`
	ControllerAddress string `json:"controller_address"`
	ControllerID      string `json:"controller_id"`
	// ControllerFingerprint records which root was pinned at enrollment, so an
	// operator can compare it against the controller's own reported fingerprint
	// without opening the PEM.
	ControllerFingerprint string    `json:"controller_fingerprint"`
	EnrolledAt            time.Time `json:"enrolled_at"`
}

// EnsureStateDir creates the state directory with restrictive permissions.
//
// It validates an EXISTING directory's permissions rather than silently
// accepting them. On a directory that is group- or world-accessible, the 0600
// key inside can still be read by anyone who can become the directory's owner or
// by any process that wins a race during file creation — so a permissive state
// directory is reported, not repaired, because repairing it silently would hide
// that the key may already have been exposed.
func EnsureStateDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("nodeagent: state directory is required")
	}
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err = os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("nodeagent: create state directory: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("nodeagent: stat state directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("nodeagent: %s exists and is not a directory", dir)
	}
	// Windows does not express POSIX permission bits; checking there would
	// produce a false warning on every install, so the check is POSIX-only. This
	// is a real limitation, stated rather than papered over: on Windows the
	// agent relies on the ACL inherited from the state directory.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return fmt.Errorf(
				"nodeagent: state directory %s has mode %04o; it must not be accessible to group or others (chmod 700)",
				dir, mode)
		}
	}
	return nil
}

// SaveConfig writes the non-secret configuration.
func SaveConfig(dir string, cfg Config) error {
	if err := EnsureStateDir(dir); err != nil {
		return err
	}
	raw, err := marshalJSON(cfg)
	if err != nil {
		return fmt.Errorf("nodeagent: encode configuration: %w", err)
	}
	path := filepath.Join(dir, configFile)
	// Written with a temporary file and a rename so an interrupted write cannot
	// leave a half-written config that the next start would fail to parse.
	return writeFileAtomic(path, raw, 0o600)
}

// LoadConfig reads the non-secret configuration.
func LoadConfig(dir string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(filepath.Join(dir, configFile)) //nolint:gosec // G304: dir is the operator-supplied state directory; the file name is a fixed constant
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, fmt.Errorf("nodeagent: no configuration in %s (has this node been enrolled?): %w", dir, err)
		}
		return cfg, fmt.Errorf("nodeagent: read configuration: %w", err)
	}
	if err := decodeJSONStrict(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("nodeagent: parse configuration: %w", err)
	}
	if cfg.ServerID == "" || cfg.ControllerID == "" || cfg.ControllerAddress == "" {
		return cfg, errors.New("nodeagent: configuration is incomplete; re-enrollment is required")
	}
	return cfg, nil
}

// SaveIdentity writes the node certificate, its private key, and the pinned
// controller root.
//
// The certificate and key go into one file because they are only meaningful
// together: a state directory containing a certificate whose key is missing is
// not a partially-working node, it is a node that cannot authenticate at all.
func SaveIdentity(dir string, leaf *pki.Leaf, controllerRootPEM []byte) error {
	if err := EnsureStateDir(dir); err != nil {
		return err
	}
	if leaf == nil {
		return errors.New("nodeagent: identity is required")
	}
	if len(controllerRootPEM) == 0 {
		return errors.New("nodeagent: controller root is required")
	}
	if err := writeFileAtomic(filepath.Join(dir, identityFile), []byte(leaf.Encode()), identityMode); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, controllerCAFile), controllerRootPEM, identityMode)
}

// LoadState reads the identity, the pinned root, and the configuration, and
// validates that they agree.
//
// The agreement check is the point of loading them together: the configuration
// names a controller id, and a pinned root that belongs to a DIFFERENT authority
// would produce an agent that refuses every connection from its own controller
// with no hint as to why. Catching it here names the actual problem.
func LoadState(dir string) (*State, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, err
	}
	identityRaw, err := os.ReadFile(filepath.Join(dir, identityFile)) //nolint:gosec // G304: dir is the operator-supplied state directory; the file name is a fixed constant
	if err != nil {
		return nil, fmt.Errorf("nodeagent: read identity: %w", err)
	}
	if err = checkPrivateMode(filepath.Join(dir, identityFile)); err != nil {
		return nil, err
	}
	leaf, err := pki.DecodeLeaf(string(identityRaw))
	if err != nil {
		return nil, fmt.Errorf("nodeagent: decode identity: %w", err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, controllerCAFile)) //nolint:gosec // G304: dir is the operator-supplied state directory; the file name is a fixed constant
	if err != nil {
		return nil, fmt.Errorf("nodeagent: read pinned controller root: %w", err)
	}

	// The certificate's own identity must match the configured server id, or
	// this node would authenticate as somebody else.
	id, err := leaf.Identity()
	if err != nil {
		return nil, fmt.Errorf("nodeagent: identity has no usable name: %w", err)
	}
	if id.ID != cfg.ServerID {
		return nil, fmt.Errorf(
			"nodeagent: stored certificate names %q but the configuration names %q; re-enrollment is required",
			id.ID, cfg.ServerID)
	}
	// The pinned root must be usable as a verifier for THIS controller. Building
	// the verifier here means a mismatched or expired root fails at load with a
	// clear message instead of at the first heartbeat.
	if _, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: rootPEM,
		Kind:    pki.KindController,
		ID:      cfg.ControllerID,
	}); err != nil {
		return nil, fmt.Errorf("nodeagent: pinned controller root does not match controller %q: %w",
			cfg.ControllerID, err)
	}

	return &State{
		Dir:               dir,
		ServerID:          cfg.ServerID,
		ControllerAddress: cfg.ControllerAddress,
		ControllerID:      cfg.ControllerID,
		Identity:          leaf,
		ControllerRootPEM: rootPEM,
	}, nil
}

// checkPrivateMode refuses to use a private key that other local users can read.
//
// It is a hard failure rather than a warning because continuing would mean
// authenticating with a credential that may already have been copied, and no
// later action can undo that: the only correct response is to stop and
// re-enroll.
func checkPrivateMode(path string) error {
	if runtime.GOOS == "windows" {
		// POSIX mode bits are not meaningful here; see EnsureStateDir.
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("nodeagent: stat identity: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf(
			"nodeagent: identity file %s has mode %04o; the node private key must not be readable by group or others (chmod 600)",
			path, mode)
	}
	return nil
}
