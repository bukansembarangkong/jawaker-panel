// Package rbac evaluates authorization decisions.
//
// The rules here are the authoritative enforcement point (SECURITY.md s5:
// "Authorization happens in backend policy enforcement, never only in UI").
// UI checks are a convenience for hiding unusable controls; they are never
// the reason a request is allowed.
//
// Model:
//   - a permission is granted only by an explicit allowlist entry;
//   - grants are scoped (global / server / project / resource) and a scoped
//     grant satisfies only requests within that scope;
//   - expired, revoked, and IP-restricted bindings do not grant anything;
//   - high-risk permissions additionally require step-up elevation, which is
//     a property of the SESSION, not of the role.
//
// Anything not explicitly allowed is denied. There is no fallback branch that
// permits an action because it "looks harmless".
package rbac

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// ScopeKind identifies how broadly a grant applies.
type ScopeKind string

const (
	ScopeGlobal   ScopeKind = "global"
	ScopeServer   ScopeKind = "server"
	ScopeProject  ScopeKind = "project"
	ScopeResource ScopeKind = "resource"
)

// Scope is the resource instance a permission is requested against.
//
// A global permission (e.g. "updates.manage") is satisfied by any global
// grant holding it. A project-scoped permission (e.g. "site.delete") requires
// a grant whose ScopeID equals the requested project.
type Scope struct {
	Kind ScopeKind
	// ID is the concrete resource id. Empty only for ScopeGlobal.
	ID string
}

// GlobalScope returns the installation-wide scope.
func GlobalScope() Scope { return Scope{Kind: ScopeGlobal} }

// ServerScope returns the scope for one server.
func ServerScope(serverID string) Scope { return Scope{Kind: ScopeServer, ID: serverID} }

// ProjectScope returns the scope for one project.
func ProjectScope(projectID string) Scope { return Scope{Kind: ScopeProject, ID: projectID} }

// ResourceScope returns the scope for one module-defined resource.
func ResourceScope(resourceID string) Scope { return Scope{Kind: ScopeResource, ID: resourceID} }

// Validate rejects malformed scopes so a mistyped call site fails loudly
// instead of silently matching nothing (or worse, matching broadly).
func (s Scope) Validate() error {
	switch s.Kind {
	case ScopeGlobal:
		if s.ID != "" {
			return fmt.Errorf("rbac: global scope must not carry an id (got %q)", s.ID)
		}
	case ScopeServer, ScopeProject, ScopeResource:
		if strings.TrimSpace(s.ID) == "" {
			return fmt.Errorf("rbac: %s scope requires a resource id", s.Kind)
		}
	default:
		return fmt.Errorf("rbac: unknown scope kind %q", s.Kind)
	}
	return nil
}

// Grant is one resolved permission binding for a principal.
type Grant struct {
	Permission string
	// Scope the grant was issued for.
	Scope Scope
	// ExpiresAt is nil for a permanent grant.
	ExpiresAt *time.Time
	// AllowedCIDRs restricts the grant to specific client networks.
	AllowedCIDRs []netip.Prefix
	// RevokedAt marks a grant that must be ignored even if still stored.
	RevokedAt *time.Time
	// RequiresStepUp mirrors the permission's risk classification.
	RequiresStepUp bool
}

// Principal is the authenticated actor requesting an action.
type Principal struct {
	// UserID is empty for service/system principals.
	UserID string
	// Grants is the resolved set of bindings for this principal.
	Grants []Grant
	// ElevatedUntil, when in the future, satisfies step-up requirements.
	ElevatedUntil *time.Time
	// ClientAddr is the source address; empty when unknown (must not satisfy
	// an IP-restricted grant).
	ClientAddr netip.Addr
	// Impersonating marks a read-only impersonation session. Such a session
	// may never perform mutations (PRD s5.4: read-only by default).
	Impersonating bool
}

// Request is one authorization question.
type Request struct {
	Permission string
	Scope      Scope
	// Mutating marks state-changing requests, which impersonation forbids.
	Mutating bool
	// Now supplies the clock; zero means time.Now(). Injected for tests and
	// for consistency across a single request.
	Now time.Time
}

// Decision is the outcome of an authorization check, including the reason so
// audit records can explain denials without guesswork.
type Decision struct {
	Allowed bool
	// Reason is a stable, non-secret explanation suitable for audit logs.
	Reason string
	// HasGrant reports that a matching, in-scope, unexpired grant exists. When
	// Allowed is false and HasGrant is true the denial is a policy condition
	// rather than a missing permission — the HTTP layer maps that to a step-up
	// challenge instead of a bare 403, without parsing Reason.
	HasGrant bool
	// RequiresStepUp is set when the only blocker is the absence of a live
	// elevation window.
	RequiresStepUp bool
}

var (
	// ErrMalformedScope is returned when the request scope is invalid.
	ErrMalformedScope = errors.New("rbac: malformed scope")
)

// Authorize decides whether the principal may perform the request.
//
// Deny-by-default: the only path to Allowed=true is finding a matching,
// unexpired, unrevoked grant whose scope covers the request and whose IP
// restrictions and step-up requirements are satisfied.
func Authorize(p Principal, r Request) (Decision, error) {
	if strings.TrimSpace(r.Permission) == "" {
		return Decision{Reason: "permission required"}, nil
	}
	if err := r.Scope.Validate(); err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrMalformedScope, err)
	}

	now := r.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Impersonation is read-only unless the platform explicitly grants more.
	// Enforced here rather than at call sites so it cannot be forgotten.
	if p.Impersonating && r.Mutating {
		return Decision{Reason: "impersonation session is read-only"}, nil
	}

	// Walk the grants, remembering the most specific reason a matching grant was
	// blocked. Without this, a denial caused by an IP restriction or an expired
	// binding is indistinguishable from holding no grant at all, and the UI could
	// not tell "you may not" from "not right now, from here".
	blocked := ""
	for _, g := range p.Grants {
		if g.Permission != r.Permission {
			continue
		}
		if !covers(g.Scope, r.Scope) {
			continue
		}
		if g.RevokedAt != nil && !g.RevokedAt.After(now) {
			blocked = firstReason(blocked, "grant revoked")
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
			blocked = firstReason(blocked, "grant expired")
			continue
		}
		if !ipAllowed(g.AllowedCIDRs, p.ClientAddr) {
			blocked = firstReason(blocked, "client address outside allowed range")
			continue
		}
		if (g.RequiresStepUp || requiresStepUpFor(r)) && !elevated(p, now) {
			// A grant exists, only the session's elevation window is missing.
			// The UI prompts for re-authentication rather than refusing
			// outright, which is why this is reported separately from a plain
			// denial.
			return Decision{
				Reason:         "step-up authentication required",
				HasGrant:       true,
				RequiresStepUp: true,
			}, nil
		}
		return Decision{Allowed: true, Reason: "granted", HasGrant: true}, nil
	}

	if blocked != "" {
		return Decision{Reason: blocked, HasGrant: true}, nil
	}
	return Decision{Reason: "no matching grant"}, nil
}

// elevated reports whether the principal holds a live elevation window.
func elevated(p Principal, now time.Time) bool {
	return p.ElevatedUntil != nil && p.ElevatedUntil.After(now)
}

// firstReason keeps the first explanation and ignores later ones, so the most
// specific cause wins when several grants are blocked for different reasons.
func firstReason(existing, candidate string) string {
	if existing != "" {
		return existing
	}
	return candidate
}

// requiresStepUpFor reports whether the request itself demands elevation
// beyond what its grant declares.
//
// This only applies to MUTATING requests. Reading through a permission whose
// name merely ends in ".delete" (or starts with "firewall."/"terminal.") must
// not demand elevation, otherwise legitimate read paths — listing what may be
// deleted, rendering the firewall view — would be blocked and the UI could
// not even show the user what they are allowed to change.
//
// The risk classification still comes from the catalog: grants seeded from
// migration 0007 carry RequiresStepUp for terminal.root, firewall.manage,
// platform.manage, users.manage, roles.manage, updates.manage, server.enroll,
// server.delete, project.delete, site.delete, database.delete, backup.restore,
// backup.delete, secrets.rotate, network.manage, modules.install,
// security.manage, impersonation.readonly, and terminal.project. This function
// is the defense-in-depth backstop for a catalog entry that forgot the flag.
func requiresStepUpFor(r Request) bool {
	if !r.Mutating {
		return false
	}
	switch {
	case strings.HasSuffix(r.Permission, ".delete"):
		return true
	case strings.HasPrefix(r.Permission, "terminal."):
		return true
	case strings.HasPrefix(r.Permission, "firewall."):
		return true
	case strings.HasPrefix(r.Permission, "impersonation."):
		return true
	}
	return false
}

// covers reports whether a granted scope satisfies a requested scope.
//
// A global grant covers every scope. Scoped grants cover their own scope and
// the global request only if the request is inherently global — which cannot
// happen because a global-scoped permission is requested with GlobalScope and
// a project-scoped permission is never requested globally. Keeping global
// grants broad is intentional: Platform Owner must be able to act anywhere.
func covers(granted, requested Scope) bool {
	if granted.Kind == ScopeGlobal {
		return true
	}
	if requested.Kind == ScopeGlobal {
		// Only a global grant may satisfy a global request; handled above.
		return false
	}
	return granted.Kind == requested.Kind && granted.ID == requested.ID
}

// ipAllowed reports whether the client address satisfies the grant's CIDR
// restrictions. An empty restriction list allows any address. An unknown
// client address does NOT satisfy a restriction: fail closed.
func ipAllowed(allowed []netip.Prefix, addr netip.Addr) bool {
	if len(allowed) == 0 {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseCIDRs converts configured CIDR strings into prefixes, rejecting any
// malformed entry rather than silently ignoring it (a silently dropped
// restriction would widen access).
func ParseCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			// Accept a bare address as a /32 or /128 host restriction.
			if addr, addrErr := netip.ParseAddr(v); addrErr == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				return nil, fmt.Errorf("rbac: invalid CIDR %q: %w", v, err)
			}
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// ParseAddr parses a client address, tolerating a host:port form. It returns
// an invalid Addr (not an error) when the input is empty, so callers can pass
// through "address unknown" without special-casing.
func ParseAddr(value string) netip.Addr {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.Unmap()
		}
	}
	return netip.Addr{}
}

// EffectivePermissions returns the distinct permissions a principal holds
// within a scope at the given time. Used to render permission-aware UI and to
// answer "what can this session do?" without re-deriving it per widget.
func EffectivePermissions(p Principal, scope Scope, now time.Time) []string {
	if now.IsZero() {
		now = time.Now()
	}
	set := make(map[string]struct{}, len(p.Grants))
	for _, g := range p.Grants {
		if !covers(g.Scope, scope) {
			continue
		}
		if g.RevokedAt != nil && !g.RevokedAt.After(now) {
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
			continue
		}
		if !ipAllowed(g.AllowedCIDRs, p.ClientAddr) {
			continue
		}
		set[g.Permission] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
