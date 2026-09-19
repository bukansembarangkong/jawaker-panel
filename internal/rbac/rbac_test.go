package rbac

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var (
	testNow      = time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	testClientIP = netip.MustParseAddr("203.0.113.10")
)

func grant(perm string, scope Scope) Grant {
	return Grant{Permission: perm, Scope: scope}
}

// --- Deny by default --------------------------------------------------------

// The single most important property: an empty principal gets nothing.
func TestDenyByDefault(t *testing.T) {
	p := Principal{UserID: "u1"}
	for _, perm := range []string{"site.read", "site.delete", "platform.manage", "updates.manage"} {
		d, err := Authorize(p, Request{Permission: perm, Scope: GlobalScope(), Now: testNow})
		if err != nil {
			t.Fatalf("Authorize(%s): %v", perm, err)
		}
		if d.Allowed {
			t.Errorf("%s allowed with no grants", perm)
		}
	}
}

func TestDenyWhenPermissionNotGranted(t *testing.T) {
	p := Principal{Grants: []Grant{grant("site.read", ProjectScope("p1"))}}
	d, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("ungranted permission allowed")
	}
	if d.Reason != "no matching grant" {
		t.Errorf("reason = %q, want %q", d.Reason, "no matching grant")
	}
}

// --- Scope enforcement ------------------------------------------------------

func TestProjectGrantDoesNotCoverOtherProject(t *testing.T) {
	p := Principal{Grants: []Grant{grant("site.delete", ProjectScope("p1"))}}
	d, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p2"), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("project grant leaked into a different project")
	}
}

func TestProjectGrantDoesNotSatisfyGlobalRequest(t *testing.T) {
	p := Principal{Grants: []Grant{grant("updates.manage", ProjectScope("p1"))}}
	d, _ := Authorize(p, Request{Permission: "updates.manage", Scope: GlobalScope(), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("project-scoped grant satisfied a global request")
	}
}

func TestGlobalGrantCoversEveryScope(t *testing.T) {
	// Uses a non-destructive permission so this test isolates SCOPE matching.
	// Destructive permissions additionally require step-up, which is covered
	// by the dedicated step-up tests below.
	p := Principal{Grants: []Grant{grant("site.read", GlobalScope())}}
	for _, scope := range []Scope{GlobalScope(), ServerScope("s1"), ProjectScope("p1"), ResourceScope("r1")} {
		d, err := Authorize(p, Request{Permission: "site.read", Scope: scope, Now: testNow})
		if err != nil {
			t.Fatalf("Authorize(%v): %v", scope, err)
		}
		if !d.Allowed {
			t.Errorf("global grant did not cover scope %v/%s: %s", scope.Kind, scope.ID, d.Reason)
		}
	}
}

// A global grant of a destructive permission covers every scope, but still
// demands elevation for the mutating case.
func TestGlobalDestructiveGrantCoversScopeButNeedsStepUp(t *testing.T) {
	future := testNow.Add(5 * time.Minute)
	for _, scope := range []Scope{ServerScope("s1"), ProjectScope("p1"), ResourceScope("r1")} {
		denied, _ := Authorize(Principal{Grants: []Grant{grant("site.delete", GlobalScope())}},
			Request{Permission: "site.delete", Scope: scope, Mutating: true, Now: testNow})
		if denied.Allowed {
			t.Errorf("scope %v: destructive global grant allowed without elevation", scope.Kind)
		}

		allowed, _ := Authorize(Principal{
			ElevatedUntil: &future,
			Grants:        []Grant{grant("site.delete", GlobalScope())},
		}, Request{Permission: "site.delete", Scope: scope, Mutating: true, Now: testNow})
		if !allowed.Allowed {
			t.Errorf("scope %v: elevated destructive global grant denied: %s", scope.Kind, allowed.Reason)
		}
	}
}

func TestServerScopeIsNotProjectScope(t *testing.T) {
	p := Principal{Grants: []Grant{grant("firewall.manage", ServerScope("s1"))}}
	d, _ := Authorize(p, Request{Permission: "firewall.manage", Scope: ProjectScope("s1"), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("same id under a different scope kind was treated as a match")
	}
}

// --- Expiry and revocation --------------------------------------------------

func TestExpiredGrantDenied(t *testing.T) {
	past := testNow.Add(-time.Minute)
	p := Principal{Grants: []Grant{{
		Permission: "site.read",
		Scope:      GlobalScope(),
		ExpiresAt:  &past,
	}}}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: GlobalScope(), Now: testNow})
	if d.Allowed {
		t.Error("expired grant allowed")
	}
}

func TestFutureExpiryAllowed(t *testing.T) {
	future := testNow.Add(time.Minute)
	p := Principal{Grants: []Grant{{
		Permission: "site.read",
		Scope:      GlobalScope(),
		ExpiresAt:  &future,
	}}}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: GlobalScope(), Now: testNow})
	if !d.Allowed {
		t.Error("grant valid at evaluation time was denied")
	}
}

func TestRevokedGrantDenied(t *testing.T) {
	past := testNow.Add(-time.Minute)
	p := Principal{Grants: []Grant{{
		Permission: "site.read",
		Scope:      GlobalScope(),
		RevokedAt:  &past,
	}}}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: GlobalScope(), Now: testNow})
	if d.Allowed {
		t.Error("revoked grant allowed")
	}
}

// --- IP restrictions --------------------------------------------------------

func TestIPRestrictionAllowsInsideRange(t *testing.T) {
	prefixes, err := ParseCIDRs([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	p := Principal{
		ClientAddr: testClientIP,
		Grants:     []Grant{{Permission: "site.read", Scope: GlobalScope(), AllowedCIDRs: prefixes}},
	}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: GlobalScope(), Now: testNow})
	if !d.Allowed {
		t.Error("address inside the allowed range was denied")
	}
}

func TestIPRestrictionDeniesOutsideRange(t *testing.T) {
	prefixes, _ := ParseCIDRs([]string{"203.0.113.0/24"})
	p := Principal{
		ClientAddr: netip.MustParseAddr("198.51.100.5"),
		Grants:     []Grant{{Permission: "site.read", Scope: GlobalScope(), AllowedCIDRs: prefixes}},
	}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: GlobalScope(), Now: testNow})
	if d.Allowed {
		t.Error("address outside the allowed range was allowed")
	}
}

// Fail closed: if we do not know where the request came from, an IP-restricted
// grant must not apply.
func TestIPRestrictedGrantDeniedWhenClientUnknown(t *testing.T) {
	prefixes, _ := ParseCIDRs([]string{"203.0.113.0/24"})
	p := Principal{
		ClientAddr: netip.Addr{}, // unknown
		Grants:     []Grant{{Permission: "site.read", Scope: GlobalScope(), AllowedCIDRs: prefixes}},
	}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: GlobalScope(), Now: testNow})
	if d.Allowed {
		t.Error("IP-restricted grant applied to an unknown client address")
	}
}

func TestParseCIDRsRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"not-a-cidr", "999.999.999.999/24", "10.0.0.0/99"} {
		if _, err := ParseCIDRs([]string{bad}); err == nil {
			t.Errorf("ParseCIDRs(%q) accepted, want error", bad)
		}
	}
}

func TestParseCIDRsAcceptsBareAddressAndSkipsBlanks(t *testing.T) {
	prefixes, err := ParseCIDRs([]string{"", "  ", "192.0.2.7", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefixes))
	}
	if !prefixes[0].Contains(netip.MustParseAddr("192.0.2.7")) {
		t.Error("bare address was not treated as a host restriction")
	}
}

func TestParseAddrHandlesHostPortAndEmpty(t *testing.T) {
	if got := ParseAddr("203.0.113.10:54321"); got != testClientIP {
		t.Errorf("ParseAddr(host:port) = %v, want %v", got, testClientIP)
	}
	if got := ParseAddr("  "); got.IsValid() {
		t.Errorf("ParseAddr(blank) = %v, want invalid", got)
	}
	if got := ParseAddr("garbage"); got.IsValid() {
		t.Errorf("ParseAddr(garbage) = %v, want invalid", got)
	}
}

// --- Step-up authentication -------------------------------------------------

func TestStepUpRequiredForDestructivePermission(t *testing.T) {
	p := Principal{Grants: []Grant{grant("site.delete", ProjectScope("p1"))}}
	d, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("destructive operation allowed without elevation")
	}
	if d.Reason != "step-up authentication required" {
		t.Errorf("reason = %q, want step-up prompt", d.Reason)
	}
}

func TestStepUpSatisfiedByFreshElevation(t *testing.T) {
	future := testNow.Add(5 * time.Minute)
	p := Principal{
		ElevatedUntil: &future,
		Grants:        []Grant{grant("site.delete", ProjectScope("p1"))},
	}
	d, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if !d.Allowed {
		t.Errorf("elevated session denied: %s", d.Reason)
	}
}

func TestExpiredElevationDoesNotSatisfyStepUp(t *testing.T) {
	past := testNow.Add(-time.Second)
	p := Principal{
		ElevatedUntil: &past,
		Grants:        []Grant{grant("site.delete", ProjectScope("p1"))},
	}
	d, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("stale elevation satisfied step-up")
	}
}

func TestReadOperationNeedsNoElevation(t *testing.T) {
	p := Principal{Grants: []Grant{grant("site.read", ProjectScope("p1"))}}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: ProjectScope("p1"), Now: testNow})
	if !d.Allowed {
		t.Errorf("plain read denied: %s", d.Reason)
	}
}

// A grant flagged RequiresStepUp must require elevation even for a permission
// name that does not look destructive.
func TestGrantLevelStepUpFlagIsHonoured(t *testing.T) {
	p := Principal{Grants: []Grant{{
		Permission:     "settings.manage",
		Scope:          GlobalScope(),
		RequiresStepUp: true,
	}}}
	d, _ := Authorize(p, Request{Permission: "settings.manage", Scope: GlobalScope(), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("grant-level step-up requirement ignored")
	}
}

// Destructive names require elevation even if the grant forgot to flag it, so
// a mis-seeded catalog cannot silently lower the bar.
func TestDestructiveNamesRequireStepUpWithoutFlag(t *testing.T) {
	for _, perm := range []string{
		"database.delete", "terminal.root", "firewall.manage", "impersonation.readonly", "project.delete",
	} {
		p := Principal{Grants: []Grant{grant(perm, GlobalScope())}}
		d, _ := Authorize(p, Request{Permission: perm, Scope: GlobalScope(), Mutating: true, Now: testNow})
		if d.Allowed {
			t.Errorf("%s allowed without elevation despite being destructive", perm)
		}
	}
}

// --- Impersonation ----------------------------------------------------------

func TestImpersonationCannotMutate(t *testing.T) {
	future := testNow.Add(time.Hour)
	p := Principal{
		Impersonating: true,
		ElevatedUntil: &future,
		Grants:        []Grant{grant("site.delete", ProjectScope("p1"))},
	}
	d, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if d.Allowed {
		t.Error("impersonation session performed a mutation")
	}
	if !strings.Contains(d.Reason, "read-only") {
		t.Errorf("reason = %q, want read-only explanation", d.Reason)
	}
}

func TestImpersonationCanRead(t *testing.T) {
	p := Principal{
		Impersonating: true,
		Grants:        []Grant{grant("site.read", ProjectScope("p1"))},
	}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: ProjectScope("p1"), Now: testNow})
	if !d.Allowed {
		t.Errorf("impersonation read denied: %s", d.Reason)
	}
}

// --- Malformed input --------------------------------------------------------

func TestMalformedScopeReturnsError(t *testing.T) {
	p := Principal{Grants: []Grant{grant("site.read", GlobalScope())}}
	cases := map[string]Scope{
		"global with id":     {Kind: ScopeGlobal, ID: "should-not-be-here"},
		"project without id": {Kind: ScopeProject},
		"unknown kind":       {Kind: "galaxy"},
	}
	for label, scope := range cases {
		t.Run(label, func(t *testing.T) {
			_, err := Authorize(p, Request{Permission: "site.read", Scope: scope, Now: testNow})
			if err == nil {
				t.Fatal("malformed scope accepted")
			}
			if !errors.Is(err, ErrMalformedScope) {
				t.Errorf("err = %v, want ErrMalformedScope", err)
			}
		})
	}
}

func TestEmptyPermissionDenied(t *testing.T) {
	d, err := Authorize(Principal{}, Request{Permission: "  ", Scope: GlobalScope(), Now: testNow})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("empty permission allowed")
	}
}

// --- Effective permissions --------------------------------------------------

func TestEffectivePermissionsFiltersAndSorts(t *testing.T) {
	past := testNow.Add(-time.Minute)
	p := Principal{
		ClientAddr: testClientIP,
		Grants: []Grant{
			grant("site.read", ProjectScope("p1")),
			grant("site.manage", ProjectScope("p1")),
			grant("database.read", ProjectScope("p1")),
			{Permission: "site.delete", Scope: ProjectScope("p1"), ExpiresAt: &past},
			grant("platform.manage", GlobalScope()),
			grant("site.read", ProjectScope("p2")), // different project
		},
	}
	got := EffectivePermissions(p, ProjectScope("p1"), testNow)
	want := []string{"database.read", "platform.manage", "site.manage", "site.read"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("EffectivePermissions = %v, want %v", got, want)
	}
}

func TestEffectivePermissionsExcludesUnusableGrants(t *testing.T) {
	prefixes, _ := ParseCIDRs([]string{"10.0.0.0/8"})
	past := testNow.Add(-time.Minute)
	p := Principal{
		ClientAddr: testClientIP, // outside 10.0.0.0/8
		Grants: []Grant{
			{Permission: "a.read", Scope: GlobalScope(), AllowedCIDRs: prefixes},
			{Permission: "b.read", Scope: GlobalScope(), RevokedAt: &past},
			{Permission: "c.read", Scope: GlobalScope(), ExpiresAt: &past},
			grant("d.read", GlobalScope()),
		},
	}
	got := EffectivePermissions(p, GlobalScope(), testNow)
	if strings.Join(got, ",") != "d.read" {
		t.Errorf("EffectivePermissions = %v, want [d.read]", got)
	}
}

// --- Scope helpers ----------------------------------------------------------

func TestScopeConstructorsValidate(t *testing.T) {
	for _, s := range []Scope{GlobalScope(), ServerScope("s1"), ProjectScope("p1"), ResourceScope("r1")} {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%v) = %v, want nil", s, err)
		}
	}
}

// --- Typed denial fields ----------------------------------------------------

// The HTTP layer must distinguish "you do not hold this permission" (403) from
// "you hold it but cannot use it right now" (step-up challenge, network
// restriction). Decision carries that distinction as data, so callers never
// parse the human-readable Reason.
func TestDecisionReportsStepUpAsTypedField(t *testing.T) {
	p := Principal{Grants: []Grant{grant("site.delete", ProjectScope("p1"))}}
	d, err := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allowed {
		t.Fatal("destructive mutation allowed without elevation")
	}
	if !d.HasGrant {
		t.Error("HasGrant = false, want true (a matching in-scope grant exists)")
	}
	if !d.RequiresStepUp {
		t.Error("RequiresStepUp = false, want true")
	}

	// Once elevated, the same request is allowed and the fields say so.
	elev := testNow.Add(5 * time.Minute)
	p.ElevatedUntil = &elev
	d2, _ := Authorize(p, Request{Permission: "site.delete", Scope: ProjectScope("p1"), Mutating: true, Now: testNow})
	if !d2.Allowed || !d2.HasGrant {
		t.Errorf("elevated decision = %+v, want allowed with grant", d2)
	}
	if d2.RequiresStepUp {
		t.Error("RequiresStepUp = true on an allowed decision")
	}
}

func TestDecisionDistinguishesNoGrantFromBlockedGrant(t *testing.T) {
	now := testNow
	expired := now.Add(-time.Hour)

	cases := []struct {
		name         string
		grant        Grant
		client       netip.Addr
		wantHasGrant bool
		wantStepUp   bool
		wantReason   string
	}{
		{
			name:         "no grant at all",
			grant:        grant("site.read", ProjectScope("other")),
			wantHasGrant: false,
			wantReason:   "no matching grant",
		},
		{
			name:         "expired grant",
			grant:        Grant{Permission: "site.read", Scope: ProjectScope("p1"), ExpiresAt: &expired},
			wantHasGrant: true,
			wantReason:   "grant expired",
		},
		{
			name:         "revoked grant",
			grant:        Grant{Permission: "site.read", Scope: ProjectScope("p1"), RevokedAt: &expired},
			wantHasGrant: true,
			wantReason:   "grant revoked",
		},
		{
			name:         "ip restricted grant from unknown client",
			grant:        Grant{Permission: "site.read", Scope: ProjectScope("p1"), AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
			wantHasGrant: true,
			wantReason:   "client address outside allowed range",
		},
		{
			name:         "ip restricted grant from disallowed client",
			grant:        Grant{Permission: "site.read", Scope: ProjectScope("p1"), AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
			client:       testClientIP,
			wantHasGrant: true,
			wantReason:   "client address outside allowed range",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Principal{Grants: []Grant{tc.grant}, ClientAddr: tc.client}
			d, err := Authorize(p, Request{Permission: "site.read", Scope: ProjectScope("p1"), Now: now})
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if d.Allowed {
				t.Fatalf("allowed with grant %+v", tc.grant)
			}
			if d.HasGrant != tc.wantHasGrant {
				t.Errorf("HasGrant = %v, want %v (reason %q)", d.HasGrant, tc.wantHasGrant, d.Reason)
			}
			if d.RequiresStepUp != tc.wantStepUp {
				t.Errorf("RequiresStepUp = %v, want %v", d.RequiresStepUp, tc.wantStepUp)
			}
			if d.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", d.Reason, tc.wantReason)
			}
		})
	}
}

// When several grants match and each is blocked for a different reason, the
// first explanation wins deterministically instead of depending on slice order.
func TestFirstBlockingReasonWins(t *testing.T) {
	expired := testNow.Add(-time.Hour)
	p := Principal{
		Grants: []Grant{
			{Permission: "site.read", Scope: ProjectScope("p1"), ExpiresAt: &expired},
			{Permission: "site.read", Scope: ProjectScope("p1"), RevokedAt: &expired},
		},
	}
	d, _ := Authorize(p, Request{Permission: "site.read", Scope: ProjectScope("p1"), Now: testNow})
	if d.Allowed {
		t.Fatal("blocked grants allowed")
	}
	if d.Reason != "grant expired" {
		t.Errorf("Reason = %q, want %q", d.Reason, "grant expired")
	}
	if !d.HasGrant {
		t.Error("HasGrant = false, want true")
	}
}

// A usable grant must win over a blocked one regardless of order: the point of
// scanning every grant is that holding one valid path is enough.
func TestUsableGrantWinsOverBlockedGrant(t *testing.T) {
	expired := testNow.Add(-time.Hour)
	for _, order := range []string{"blocked-first", "usable-first"} {
		t.Run(order, func(t *testing.T) {
			blocked := Grant{Permission: "site.read", Scope: ProjectScope("p1"), ExpiresAt: &expired}
			usable := grant("site.read", ProjectScope("p1"))
			grants := []Grant{blocked, usable}
			if order == "usable-first" {
				grants = []Grant{usable, blocked}
			}
			d, err := Authorize(Principal{Grants: grants},
				Request{Permission: "site.read", Scope: ProjectScope("p1"), Now: testNow})
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if !d.Allowed {
				t.Errorf("denied despite a usable grant (reason %q)", d.Reason)
			}
		})
	}
}
