package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/eventstream"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
)

func fixedNow() func() time.Time {
	return func() time.Time { return time.Unix(1700000000, 0).UTC() }
}

// requestAs builds an authenticated request carrying the given global grants.
func requestAs(t *testing.T, userID string, grants ...rbac.Grant) *http.Request {
	t.Helper()
	ctx := auth.WithPrincipal(t.Context(), auth.Principal{
		Principal: rbac.Principal{UserID: userID, Grants: grants},
		UserID:    userID,
	})
	return httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
}

// globalGrants turns permission names into global, non-expiring grants.
func globalGrants(perms ...string) []rbac.Grant {
	grants := make([]rbac.Grant, 0, len(perms))
	for _, p := range perms {
		grants = append(grants, rbac.Grant{
			Permission: p,
			Scope:      rbac.GlobalScope(),
		})
	}
	return grants
}

// A request with no principal must never be authorized: an SSE subscription is
// exactly as sensitive as the REST read of the same data.
func TestAuthorizeTopicRequiresPrincipal(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/jobs", nil)
	if authorizeTopic(req, eventstream.TopicJobs, fixedNow()) {
		t.Error("an unauthenticated request was authorized for the jobs stream")
	}
	if authorizeTopic(req, eventstream.UserTopic("someone"), fixedNow()) {
		t.Error("an unauthenticated request was authorized for a personal stream")
	}
}

// A personal topic belongs to exactly one user. Another authenticated user must
// be refused even holding generous permissions, because no permission grants
// access to someone else's mailbox.
func TestAuthorizeTopicPersonalIsOwnerOnly(t *testing.T) {
	perms := globalGrants("users.read", "jobs.read")

	// Owner may subscribe to their own stream.
	if !authorizeTopic(requestAs(t, "user-a", perms...), eventstream.UserTopic("user-a"), fixedNow()) {
		t.Error("the owner was refused their own personal stream")
	}
	// A different user may not, despite holding a broad read permission.
	if authorizeTopic(requestAs(t, "user-b", perms...), eventstream.UserTopic("user-a"), fixedNow()) {
		t.Error("a non-owner was authorized for another user's personal stream")
	}
	// An empty id in the topic is not "the anonymous user".
	if authorizeTopic(requestAs(t, "user-a", perms...), eventstream.TopicUserPrefix, fixedNow()) {
		t.Error("an empty personal topic id was authorized")
	}
}

// Shared topics require the read permission for their data, so the SSE stream
// cannot be a way around an HTTP 403.
func TestAuthorizeTopicSharedRequiresPermission(t *testing.T) {
	withJobs := requestAs(t, "user-a", globalGrants("jobs.read")...)
	if !authorizeTopic(withJobs, eventstream.TopicJobs, fixedNow()) {
		t.Error("a caller holding jobs.read was refused the jobs stream")
	}

	withSites := requestAs(t, "user-a", globalGrants("site.read")...)
	if authorizeTopic(withSites, eventstream.TopicJobs, fixedNow()) {
		t.Error("a caller without jobs.read was authorized for the jobs stream")
	}

	withSecurity := requestAs(t, "user-a", globalGrants("security.read")...)
	if !authorizeTopic(withSecurity, eventstream.TopicIncidents, fixedNow()) {
		t.Error("a caller holding security.read was refused the incidents stream")
	}

	anonymous := requestAs(t, "user-a")
	if authorizeTopic(anonymous, eventstream.TopicIncidents, fixedNow()) {
		t.Error("a caller with no permissions was authorized for the incidents stream")
	}
}

// An unknown topic is refused rather than streamed empty: a stream that carries
// nothing is indistinguishable from a quiet system, which hides the mistake.
func TestAuthorizeTopicUnknownIsRefused(t *testing.T) {
	req := requestAs(t, "user-a", globalGrants("jobs.read")...)

	for _, topic := range []string{"", "unknown", "user:", "jobs/../secrets"} {
		if authorizeTopic(req, topic, fixedNow()) {
			t.Errorf("unknown topic %q was authorized", topic)
		}
	}
}

// Every streamed shared topic must have an explicit requirement, so adding a
// topic without deciding its permission cannot silently expose it.
func TestAllSharedTopicsHaveRequirements(t *testing.T) {
	// The set of shared topics this build knows how to publish on.
	shared := []string{eventstream.TopicJobs, eventstream.TopicIncidents}
	for _, topic := range shared {
		if _, ok := topicRequirements[topic]; !ok {
			t.Errorf("shared topic %q has no permission requirement; it would stream nothing and fail closed, but the gap should be explicit", topic)
		}
	}
}

// A clock that panics would be a programming error, but rbac evaluating to a
// denial must never fall through to allow.
func TestAuthorizeTopicDeniedByExpiredGrant(t *testing.T) {
	expired := ptrTime(time.Unix(1000, 0).UTC()) // long past
	req := requestAs(t, "user-a", rbac.Grant{
		Permission: "jobs.read",
		Scope:      rbac.GlobalScope(),
		ExpiresAt:  expired,
	})

	if authorizeTopic(req, eventstream.TopicJobs, fixedNow()) {
		t.Error("an expired grant was treated as authority")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
