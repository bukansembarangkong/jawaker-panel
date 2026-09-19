package controller

import (
	"net/http"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/eventstream"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
)

// topicRequirements maps a shared topic to the permission and scope its data
// demands over SSE.
//
// The map exists so the mapping is explicit: a new topic cannot be streamed
// until someone decides, in writing, which permission it needs. A default of
// "allow" would make every future topic readable by anyone who can open the
// stream, which is exactly the kind of silent authorization gap this project
// forbids.
var topicRequirements = map[string]struct {
	Permission string
	Scope      rbac.Scope
}{
	eventstream.TopicJobs: {
		Permission: "jobs.read",
		Scope:      rbac.GlobalScope(),
	},
	eventstream.TopicIncidents: {
		Permission: "security.read",
		// Incidents are reported per server, so the global scope here means
		// "any server": the per-server refinement arrives with the incidents
		// module, which will pass a server-scoped check instead.
		Scope: rbac.GlobalScope(),
	},
}

// authorizeTopic decides whether this request may subscribe to this topic.
//
// Personal topics require the caller to BE the user the topic names, and shared
// topics require the read permission for their data. Both paths fail closed: an
// unknown topic is refused, not streamed empty — a stream that carries nothing
// looks like a quiet system rather than a denied one.
func authorizeTopic(r *http.Request, topic string, now func() time.Time) bool {
	principal, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		return false
	}

	// Personal stream: "user:<id>" belongs to exactly one user. Subscribing to
	// someone else's is a cross-tenant read, so it is refused regardless of
	// permissions — no permission grants access to another user's mailbox.
	if strings.HasPrefix(topic, eventstream.TopicUserPrefix) {
		owner := strings.TrimPrefix(topic, eventstream.TopicUserPrefix)
		return owner != "" && principal.UserID == owner
	}

	requirement, ok := topicRequirements[topic]
	if !ok {
		return false
	}
	decision, err := rbac.Authorize(principal.Principal, rbac.Request{
		Permission: requirement.Permission,
		Scope:      requirement.Scope,
		Now:        now(),
	})
	if err != nil {
		// An evaluation error must not become access. rbac reports malformed
		// requests and clock problems here; neither is a reason to allow.
		return false
	}
	return decision.Allowed
}
