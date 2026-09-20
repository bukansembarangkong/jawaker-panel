// Package nodes implements the controller side of node management: the
// certificate authority it custodies, the server inventory, and the enrollment
// flow that turns a one-time token into a long-lived node identity.
//
// # The enrollment transaction
//
// Redemption is one database transaction, and that is the design rather than an
// implementation detail. A partial enrollment — a consumed token with no server,
// or a server with no certificate — is an installation that can neither retry
// (the token is spent) nor proceed (the identity is missing), and diagnosing it
// means reading two tables to find out which half happened.
//
// The transaction's first statement is the conditional UPDATE that claims the
// token. Its WHERE clause holds a row lock until commit, so a concurrent
// redemption blocks and then finds nothing to claim. Single-use is therefore a
// property of the database, not a check that a future caller could forget.
//
// # Certificate authority custody
//
// The two CA private keys live in internal/secret, encrypted at rest, reached
// only by reference (SECURITY.md §8: "secrets referenced by opaque IDs"). They
// are never written to the control-plane database as plaintext, never logged, and
// never returned by an API. A database dump alone does not disclose them, which
// is why the master key stays in the process environment.
package nodes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Secret references for the two authorities. They are constants because they are
// part of the installation's identity: changing one orphans every issued
// certificate, so a rename is a migration, not a configuration change.
const (
	ControllerCARef = "secret://pki/controller/ca/root"
	NodeCARef       = "secret://pki/node/ca/root"
)

// Errors callers branch on.
var (
	// ErrNotFound means the requested row does not exist, or exists but is
	// tombstoned. The two are deliberately not distinguished: a caller should
	// not be able to learn that a deleted server once had this id.
	ErrNotFound = errors.New("nodes: not found")
	// ErrTokenInvalid means an enrollment token was unknown, expired, revoked,
	// used, or minted for a different controller. ONE error for all five,
	// because distinguishing them tells an attacker holding a guessed token
	// whether the guess was structurally valid.
	ErrTokenInvalid = errors.New("nodes: enrollment token is not valid")
	// ErrNameTaken means a live server already uses the requested name.
	ErrNameTaken = errors.New("nodes: a server with that name already exists")
	// ErrNoAuthority means the installation's CA is not configured, so node
	// features cannot work. This is a configuration fact, not a fault.
	ErrNoAuthority = errors.New("nodes: certificate authority is not configured")
	// ErrStatus means a state transition was requested that the row's current
	// state does not allow.
	ErrStatus = errors.New("nodes: invalid status transition")
)

// Authority holds the installation's two certificate authorities and the
// controller's own identity.
//
// Both authorities live in one value because they must be loaded together: an
// installation with a controller CA and no node CA could authenticate itself to
// nodes but could not enroll any, and that half-configured state is better
// refused at startup than discovered during an enrollment.
type Authority struct {
	controller *pki.CA
	node       *pki.CA
	// controllerID is the singleton controller_identity row id. It is the id
	// stamped into controller certificates and bound to enrollment tokens.
	controllerID string
	// clock is injectable so lifetime decisions are testable without waiting.
	clock func() time.Time
}

// AuthorityOptions configures loading.
type AuthorityOptions struct {
	// DB is required to read the singleton controller identity.
	DB *pgxpool.Pool
	// Secrets is the secret store holding the CA keys. Required.
	Secrets *secret.Store
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
}

// LoadAuthority reads both authorities and the controller identity.
//
// It creates the controller identity row if none exists, because that id has to
// exist before any certificate can be issued and creating it here means an
// operator never has to run a setup command. It does NOT create the CAs: minting
// a new root silently would invalidate every certificate already issued, so a
// missing CA is reported and the caller decides. EnsureAuthority does the
// deliberate first-time creation.
func LoadAuthority(ctx context.Context, opts AuthorityOptions) (*Authority, error) {
	if opts.DB == nil {
		return nil, errors.New("nodes: database is required")
	}
	if opts.Secrets == nil {
		return nil, errors.New("nodes: secret store is required")
	}
	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}

	controllerID, err := ensureControllerIdentity(ctx, opts.DB)
	if err != nil {
		return nil, err
	}
	controllerCA, err := loadCA(ctx, opts.Secrets, ControllerCARef, pki.KindController)
	if err != nil {
		return nil, err
	}
	nodeCA, err := loadCA(ctx, opts.Secrets, NodeCARef, pki.KindNode)
	if err != nil {
		return nil, err
	}
	return &Authority{controller: controllerCA, node: nodeCA, controllerID: controllerID, clock: clock}, nil
}

// EnsureAuthority loads the authorities, creating them on first run.
//
// Creation is separated from loading so that "the root is missing" is a
// deliberate act with a clear audit trail rather than a side effect of starting
// the controller. A silently regenerated root would mean every enrolled node
// stops authenticating, and the operator would have no record of why.
//
// created reports whether this call minted new roots, so a caller can log the
// event and record its fingerprints.
func EnsureAuthority(ctx context.Context, opts AuthorityOptions) (auth *Authority, created bool, err error) {
	if opts.DB == nil {
		return nil, false, errors.New("nodes: database is required")
	}
	if opts.Secrets == nil {
		return nil, false, errors.New("nodes: secret store is required")
	}
	controllerID, err := ensureControllerIdentity(ctx, opts.DB)
	if err != nil {
		return nil, false, err
	}

	controllerCA, madeController, err := ensureCA(ctx, opts.Secrets, ControllerCARef, "JAWAKER Controller CA", pki.KindController, opts.Now)
	if err != nil {
		return nil, false, err
	}
	nodeCA, madeNode, err := ensureCA(ctx, opts.Secrets, NodeCARef, "JAWAKER Node CA", pki.KindNode, opts.Now)
	if err != nil {
		return nil, false, err
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	return &Authority{
		controller:   controllerCA,
		node:         nodeCA,
		controllerID: controllerID,
		clock:        clock,
	}, madeController || madeNode, nil
}

// ensureControllerIdentity returns the singleton id, creating the row if needed.
//
// The INSERT relies on the database's singleton unique index rather than a
// SELECT-then-INSERT: two controllers starting at once would both see "no row"
// and both insert. ON CONFLICT DO NOTHING plus a follow-up SELECT makes the race
// harmless, and the row that wins is the one everyone uses.
func ensureControllerIdentity(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO controller_identity (name) VALUES ('jawaker')
		ON CONFLICT (singleton) DO NOTHING
		RETURNING id`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("nodes: create controller identity: %w", err)
	}
	// The row already existed; read it.
	if err := pool.QueryRow(ctx, `SELECT id FROM controller_identity`).Scan(&id); err != nil {
		return "", fmt.Errorf("nodes: read controller identity: %w", err)
	}
	return id, nil
}

// loadCA reads an authority from the secret store.
func loadCA(ctx context.Context, secrets *secret.Store, ref string, want pki.Kind) (*pki.CA, error) {
	encoded, err := secrets.Open(ctx, ref)
	if err != nil {
		if errors.Is(err, secret.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrNoAuthority, ref)
		}
		return nil, fmt.Errorf("nodes: open %s: %w", ref, err)
	}
	ca, err := pki.DecodeCA(encoded)
	if err != nil {
		return nil, fmt.Errorf("nodes: decode %s: %w", ref, err)
	}
	// The kind is recovered from the certificate itself, but checking it against
	// the expected reference catches the one mistake that matters: a node CA
	// stored under the controller reference, which would break the trust-domain
	// separation while looking configured.
	if ca.Kind() != want {
		return nil, fmt.Errorf("nodes: %s holds a %s authority, expected %s", ref, ca.Kind(), want)
	}
	return ca, nil
}

// ensureCA returns the stored authority, creating it if absent.
//
// Create is used rather than Set on purpose: Set would overwrite an existing
// root and silently invalidate every certificate the fleet is holding.
// ErrAlreadyExists means another controller won the race, and the stored root is
// the one to use.
func ensureCA(ctx context.Context, secrets *secret.Store, ref, commonName string, kind pki.Kind, now func() time.Time) (*pki.CA, bool, error) {
	fresh, err := newCA(commonName, kind, now)
	if err != nil {
		return nil, false, err
	}
	encoded, err := fresh.Encode()
	if err != nil {
		return nil, false, err
	}
	err = secrets.Create(ctx, ref, encoded, "JAWAKER internal "+string(kind)+" certificate authority")
	switch {
	case err == nil:
		return fresh, true, nil
	case errors.Is(err, secret.ErrAlreadyExists):
		existing, loadErr := loadCA(ctx, secrets, ref, kind)
		if loadErr != nil {
			return nil, false, loadErr
		}
		return existing, false, nil
	default:
		return nil, false, fmt.Errorf("nodes: store %s: %w", ref, err)
	}
}

// newCA mints an authority with the default lifetime.
func newCA(commonName string, kind pki.Kind, now func() time.Time) (*pki.CA, error) {
	if now == nil {
		now = time.Now
	}
	ca, err := pki.NewCA(commonName, kind, now().Add(pki.DefaultCALifetime))
	if err != nil {
		return nil, fmt.Errorf("nodes: create %s authority: %w", kind, err)
	}
	return ca, nil
}

// ControllerID returns the installation's controller identity.
func (a *Authority) ControllerID() string { return a.controllerID }

// ControllerIdentity returns the controller's own pki identity.
func (a *Authority) ControllerIdentity() pki.Identity {
	return pki.Identity{Kind: pki.KindController, ID: a.controllerID}
}

// ControllerCertPEM is the controller root, for a node to pin.
func (a *Authority) ControllerCertPEM() []byte { return a.controller.CertPEM() }

// NodeCertPEM is the node root, for the controller to pin.
func (a *Authority) NodeCertPEM() []byte { return a.node.CertPEM() }

// ControllerFingerprint identifies the pinned controller root.
func (a *Authority) ControllerFingerprint() string { return a.controller.Fingerprint() }

// NodeFingerprint identifies the pinned node root.
func (a *Authority) NodeFingerprint() string { return a.node.Fingerprint() }

// IssueControllerLeaf mints the controller's own certificate for dialing agents.
func (a *Authority) IssueControllerLeaf() (*pki.Leaf, error) {
	leaf, err := a.controller.IssueLeaf(pki.LeafParams{
		Identity: a.ControllerIdentity(),
		NotAfter: a.clock().Add(pki.DefaultLeafLifetime),
		Now:      a.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("nodes: issue controller leaf: %w", err)
	}
	return leaf, nil
}

// IssueNodeLeaf mints a certificate for one node.
func (a *Authority) IssueNodeLeaf(serverID string) (*pki.Leaf, error) {
	leaf, err := a.node.IssueLeaf(pki.LeafParams{
		Identity: pki.Identity{Kind: pki.KindNode, ID: serverID},
		NotAfter: a.clock().Add(pki.DefaultLeafLifetime),
		Now:      a.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("nodes: issue node leaf: %w", err)
	}
	return leaf, nil
}

// NodeIdentity returns the pki identity of a server.
func NodeIdentity(serverID string) pki.Identity {
	return pki.Identity{Kind: pki.KindNode, ID: serverID}
}
