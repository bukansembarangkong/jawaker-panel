package nodeagent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// TestDispatchHandlesEveryServedOperation is the drift guard the dispatch
// switch's default case promises.
//
// The switch's default comment claims every served operation has a case above
// it. That claim is only true as long as the two lists — servedOperations and
// the dispatch cases — are edited together, and nothing enforces that except
// this test. If a future operation is added to the registry and to served but
// NOT to the switch, it reaches default and is refused with an error that says
// it "reached dispatch without being served": a correct refusal, but one that
// means the operation is silently dead on every node.
//
// It runs on every platform. dispatch only depends on the executors, and an
// executor for a capability this host lacks returns UNSUPPORTED rather than
// reaching the default case — which is exactly the distinction under test. The
// test does not need nginx or systemd present; it needs to know that a case
// EXISTS for each operation, and an unsupported verdict proves that.
func TestDispatchHandlesEveryServedOperation(t *testing.T) {
	a := &Agent{
		exec:   NewExecutors(ExecutorOptions{AgentVersion: "dispatch-drift-test"}),
		now:    time.Now,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx := context.Background()

	// Every registered operation must have a dispatch case. An empty input is
	// enough: a case that decodes it will fail validation or report
	// unsupported, but only the DEFAULT case produces the drift message.
	for _, op := range nodewire.Names() {
		_, err := a.dispatch(ctx, nodewire.Request{
			Operation: op,
			RequestID: "drift-check",
			Input:     json.RawMessage(`{}`),
		})
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "reached dispatch without being served") {
			t.Errorf("operation %q has no dispatch case; it would be refused on every node", op)
		}
	}
}

// The registry and the served set are derived from the same detection, so this
// asserts the specific Phase 3 operation is served exactly when a web server was
// detected — the honest-advertisement property. On a host with no nginx it must
// NOT be served; advertising it would offer an operator a check that always fails.
func TestWebConfigValidateIsServedOnlyWithAWebServer(t *testing.T) {
	withServer := servedOperations(&Executors{
		webServer: WebServer{Path: "/usr/sbin/nginx", StagingDir: "/etc/nginx/jawaker/staging"},
	})
	without := servedOperations(&Executors{})

	// supportedOS gates it too, so on a non-Linux host neither set contains it
	// and the "with" assertion would be wrong. Assert the relationship instead:
	// whatever the platform, having a web server must not REDUCE the served set,
	// and lacking one must never serve it.
	if without[nodewire.OpWebConfigValidate] {
		t.Error("web.config.validate is served on a host with no web server detected")
	}
	if supportedOS() && !withServer[nodewire.OpWebConfigValidate] {
		t.Error("web.config.validate is not served on a supported host with a web server")
	}
}
