//go:build integration

// Integration tests for the notification platform against real PostgreSQL.
//
// The behaviors that matter here are all enforced by the database: the route
// join with its severity filter, the dedup EXISTS check, and the claim's
// FOR UPDATE SKIP LOCKED. A mock would not exercise any of them.

package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("JAWAKER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping notify integration tests")
	}
	return url
}

func setup(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	m, err := migrate.New(migrations.FS, discardLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool, ctx
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// seedUser inserts a minimal user row; notifications reference users, so the
// fixture needs a real one rather than a made-up id.
func seedUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (email, display_name, account_type)
		VALUES ($1, $2, 'platform_owner')
		RETURNING id::text`, email, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedChannel(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ctype, name string, enabled bool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO notification_channels (type, name, enabled)
		VALUES ($1, $2, $3)
		RETURNING id::text`, ctype, name, enabled).Scan(&id); err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return id
}

func seedRoute(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID, channelID, minSeverity string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO notification_routes (user_id, channel_id, min_severity)
		VALUES ($1::uuid, $2::uuid, $3)`, userID, channelID, minSeverity); err != nil {
		t.Fatalf("seed route: %v", err)
	}
}

func mustPublish(t *testing.T, ctx context.Context, pool *pgxpool.Pool, e Event) Result {
	t.Helper()
	r, err := Publish(ctx, pool, e, PublishOptions{})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return r
}

func deliveryState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) (string, int) {
	t.Helper()
	var state string
	var attempts int
	if err := pool.QueryRow(ctx,
		`SELECT state, attempt_count FROM notification_deliveries WHERE id = $1`, id).
		Scan(&state, &attempts); err != nil {
		t.Fatalf("read delivery state: %v", err)
	}
	return state, attempts
}

// Severity is a filter applied at publish time: a route asking for warnings must
// not receive info events, and must still receive warning and critical.
func TestPublishFiltersByRouteSeverity(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "warn-only@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityWarning)

	info := mustPublish(t, ctx, pool, Event{
		Event: "site.info", Severity: SeverityInfo, Title: "FYI",
	})
	if info.Enqueued != 0 {
		t.Errorf("an info event reached a warning-only route: %+v", info)
	}

	warn := mustPublish(t, ctx, pool, Event{
		Event: "site.warning", Severity: SeverityWarning, Title: "Careful",
	})
	if warn.Enqueued != 1 {
		t.Errorf("warning event not routed: %+v", warn)
	}

	crit := mustPublish(t, ctx, pool, Event{
		Event: "site.critical", Severity: SeverityCritical, Title: "Fire",
	})
	if crit.Enqueued != 1 {
		t.Errorf("critical event not routed: %+v", crit)
	}
}

// Disabled routes and disabled channels must both stop delivery: an operator who
// turns a channel off expects silence, and a half-disabled pair must not leak.
func TestDisabledRoutesAndChannelsAreSkipped(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	liveChannel := seedChannel(t, ctx, pool, ChannelInPanel, "live", true)
	deadChannel := seedChannel(t, ctx, pool, ChannelEmail, "dead", false)

	seedRoute(t, ctx, pool, user, liveChannel, SeverityInfo)
	if _, err := pool.Exec(ctx,
		`UPDATE notification_routes SET enabled = false WHERE channel_id = $1::uuid`, liveChannel); err != nil {
		t.Fatalf("disable route: %v", err)
	}
	seedRoute(t, ctx, pool, user, deadChannel, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{
		Event: "site.info", Severity: SeverityInfo, Title: "Nobody home",
	})
	if res.Enqueued != 0 || len(res.DeliveryIDs) != 0 {
		t.Errorf("a disabled route/channel still produced deliveries: %+v", res)
	}
}

// No subscribers is a normal state, not an error: Publish succeeds with zero
// enqueued so the operation that raised the event is never failed by it.
func TestPublishWithNoRecipientsIsNotAnError(t *testing.T) {
	pool, ctx := setup(t)

	res, err := Publish(ctx, pool, Event{
		Event: "site.info", Severity: SeverityInfo, Title: "Into the void",
	}, PublishOptions{})
	if err != nil {
		t.Fatalf("Publish with no recipients returned an error: %v", err)
	}
	if res.Enqueued != 0 {
		t.Errorf("enqueued = %d, want 0", res.Enqueued)
	}
}

// DESIGN_SYSTEM.md s19: the same unresolved condition is not re-notified inside
// the dedup window. The repeat is recorded as suppressed, not dropped, so the
// evidence that it happened survives.
func TestDedupSuppressesRepeatWithinWindow(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	first := mustPublish(t, ctx, pool, Event{
		Event: "server.offline", Severity: SeverityCritical, Title: "Server down",
		ResourceType: "server", ResourceID: "srv-1", DedupKey: "server:srv-1:offline",
	})
	if first.Enqueued != 1 {
		t.Fatalf("first publish enqueued %d, want 1", first.Enqueued)
	}

	second := mustPublish(t, ctx, pool, Event{
		Event: "server.offline", Severity: SeverityCritical, Title: "Server down",
		ResourceType: "server", ResourceID: "srv-1", DedupKey: "server:srv-1:offline",
	})
	if second.Enqueued != 0 || second.Suppressed != 1 {
		t.Fatalf("second publish = %+v, want enqueued 0 / suppressed 1", second)
	}
	if st, _ := deliveryState(t, ctx, pool, second.DeliveryIDs[0]); st != StateSuppressed {
		t.Errorf("repeat delivery state = %q, want suppressed", st)
	}

	// A DIFFERENT condition for the same resource is not suppressed: dedup keys
	// the condition, not the resource.
	other := mustPublish(t, ctx, pool, Event{
		Event: "server.degraded", Severity: SeverityWarning, Title: "Server degraded",
		ResourceType: "server", ResourceID: "srv-1", DedupKey: "server:srv-1:degraded",
	})
	if other.Enqueued != 1 {
		t.Errorf("a different condition was suppressed: %+v", other)
	}
}

// An expired dedup window must re-arm: a condition that has been quiet for
// longer than the window is a fresh occurrence, not a duplicate.
func TestDedupReArmsAfterWindow(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	e := Event{
		Event: "server.offline", Severity: SeverityCritical, Title: "Server down",
		ResourceType: "server", ResourceID: "srv-1", DedupKey: "server:srv-1:offline",
	}
	if r := mustPublish(t, ctx, pool, e); r.Enqueued != 1 {
		t.Fatalf("first publish = %+v", r)
	}

	// Use a zero-length window so the previous delivery is already outside it.
	res, err := Publish(ctx, pool, e, PublishOptions{DedupWindow: time.Nanosecond})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.Enqueued != 1 {
		t.Errorf("an expired window did not re-arm: %+v", res)
	}
}

// The delivery loop hands a pending row to the right sender and records success.
func TestDeliverOnceSendsAndMarksDelivered(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{
		Event: "deployment.completed", Severity: SeverityInfo, Title: "Deployed",
		Body: "v1.2.3 is live", Payload: map[string]any{"version": "1.2.3"},
	})
	id := res.DeliveryIDs[0]

	var sent atomic.Int32
	var gotTitle, gotBody string
	var mu sync.Mutex
	senders := map[string]Sender{
		ChannelInPanel: func(_ context.Context, d Delivery) error {
			sent.Add(1)
			mu.Lock()
			gotTitle, gotBody = d.Title, d.Body
			mu.Unlock()
			return nil
		},
	}

	n, err := DeliverOnce(ctx, pool, senders, ClaimOptions{})
	if err != nil {
		t.Fatalf("DeliverOnce: %v", err)
	}
	if n != 1 || sent.Load() != 1 {
		t.Fatalf("attempted %d, sender called %d, want 1/1", n, sent.Load())
	}
	if st, _ := deliveryState(t, ctx, pool, id); st != StateDelivered {
		t.Errorf("state = %q, want delivered", st)
	}
	// The rendered summary survived into the payload.
	mu.Lock()
	title, body := gotTitle, gotBody
	mu.Unlock()
	if title != "Deployed" || body != "v1.2.3 is live" {
		t.Errorf("sender saw title=%q body=%q", title, body)
	}
	// And it now shows in the inbox.
	inbox, err := Inbox(ctx, pool, user, 50)
	if err != nil {
		t.Fatalf("Inbox: %v", err)
	}
	if len(inbox) != 1 || inbox[0].ID != id {
		t.Fatalf("inbox = %+v, want the one delivered notification", inbox)
	}
}

// A failing sender does not lose the notification: it goes back to pending with
// a bumped attempt and a future next_attempt_at, then retries.
func TestDeliverOnceRetriesWithBackoff(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelEmail, "email", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{
		Event: "backup.failed", Severity: SeverityCritical, Title: "Backup failed",
	})
	id := res.DeliveryIDs[0]

	var calls atomic.Int32
	senders := map[string]Sender{
		ChannelEmail: func(_ context.Context, _ Delivery) error {
			calls.Add(1)
			return errors.New("smtp connection refused")
		},
	}

	if _, err := DeliverOnce(ctx, pool, senders, ClaimOptions{}); err != nil {
		t.Fatalf("DeliverOnce: %v", err)
	}
	st, attempts := deliveryState(t, ctx, pool, id)
	if st != StatePending {
		t.Errorf("state after failure = %q, want pending (retryable)", st)
	}
	if attempts != 1 {
		t.Errorf("attempt_count = %d, want 1", attempts)
	}
	var lastErr string
	var nextDue bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(last_error,''), next_attempt_at > now() FROM notification_deliveries WHERE id=$1`, id).
		Scan(&lastErr, &nextDue); err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	if lastErr != "smtp connection refused" {
		t.Errorf("last_error = %q", lastErr)
	}
	if !nextDue {
		t.Error("next_attempt_at is not in the future after a backoff")
	}

	// It is not immediately re-claimable while the backoff is in effect.
	if n, err := DeliverOnce(ctx, pool, senders, ClaimOptions{}); err != nil {
		t.Fatalf("second DeliverOnce: %v", err)
	} else if n != 0 {
		t.Errorf("a backing-off delivery was re-claimed immediately (%d)", n)
	}
	if calls.Load() != 1 {
		t.Errorf("sender called %d times, want 1 (backoff held)", calls.Load())
	}
}

// Once attempts are exhausted the delivery is dead-lettered, and Redeliver puts
// it back with a fresh budget so the retry is not a no-op.
func TestDeadLetterThenRedeliver(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelTelegram, "tg", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{
		Event: "server.offline", Severity: SeverityCritical, Title: "Down",
	})
	id := res.DeliveryIDs[0]

	// max_attempts defaults to 5; drive it to exhaustion by clearing the backoff
	// between failures rather than sleeping through it.
	fail := map[string]Sender{
		ChannelTelegram: func(_ context.Context, _ Delivery) error { return errors.New("tg down") },
	}
	for i := 0; i < 5; i++ {
		if _, err := pool.Exec(ctx,
			`UPDATE notification_deliveries SET next_attempt_at = now() WHERE id=$1`, id); err != nil {
			t.Fatalf("clear backoff: %v", err)
		}
		if _, err := DeliverOnce(ctx, pool, fail, ClaimOptions{}); err != nil {
			t.Fatalf("DeliverOnce attempt %d: %v", i, err)
		}
	}
	st, attempts := deliveryState(t, ctx, pool, id)
	if st != StateDeadLetter {
		t.Fatalf("state = %q, want dead_letter after %d attempts", st, attempts)
	}
	if attempts != 5 {
		t.Errorf("attempt_count = %d, want 5", attempts)
	}

	dl, err := DeadLetters(ctx, pool, 50)
	if err != nil {
		t.Fatalf("DeadLetters: %v", err)
	}
	if len(dl) != 1 || dl[0].ID != id {
		t.Fatalf("dead letters = %+v, want the one failed delivery", dl)
	}

	if err := Redeliver(ctx, pool, id); err != nil {
		t.Fatalf("Redeliver: %v", err)
	}
	st, attempts = deliveryState(t, ctx, pool, id)
	if st != StatePending || attempts != 0 {
		t.Errorf("after redeliver: state=%q attempts=%d, want pending/0", st, attempts)
	}

	// A successful sender now delivers it.
	ok := map[string]Sender{ChannelTelegram: func(_ context.Context, _ Delivery) error { return nil }}
	if _, err := DeliverOnce(ctx, pool, ok, ClaimOptions{}); err != nil {
		t.Fatalf("DeliverOnce after redeliver: %v", err)
	}
	if st, _ := deliveryState(t, ctx, pool, id); st != StateDelivered {
		t.Errorf("state = %q, want delivered after successful redelivery", st)
	}

	// Redelivering something that is not dead-lettered is refused, not silent.
	if err := Redeliver(ctx, pool, id); err == nil {
		t.Error("Redeliver of a delivered notification succeeded")
	}
	if err := Redeliver(ctx, pool, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Redeliver of unknown id = %v, want ErrNotFound", err)
	}
}

// A channel with no registered sender must NOT burn attempts: an unconfigured
// channel is a deployment state, and dead-lettering it would silently discard
// notifications the operator can still deliver by enabling the sender.
func TestUnconfiguredChannelDoesNotConsumeAttempts(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelWebhook, "hook", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{
		Event: "site.info", Severity: SeverityInfo, Title: "Info",
	})
	id := res.DeliveryIDs[0]

	// No sender registered for webhook.
	n, err := DeliverOnce(ctx, pool, map[string]Sender{}, ClaimOptions{})
	if err != nil {
		t.Fatalf("DeliverOnce: %v", err)
	}
	if n != 0 {
		t.Errorf("attempted %d with no matching sender, want 0", n)
	}
	st, attempts := deliveryState(t, ctx, pool, id)
	if st != StatePending {
		t.Errorf("state = %q, want pending (returned, not failed)", st)
	}
	if attempts != 0 {
		t.Errorf("attempt_count = %d, want 0 (no attempt consumed)", attempts)
	}
}

// Channel-type filtering lets independent loops run without stealing each
// other's work.
func TestClaimFiltersByChannelType(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	panel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	email := seedChannel(t, ctx, pool, ChannelEmail, "email", true)
	seedRoute(t, ctx, pool, user, panel, SeverityInfo)
	seedRoute(t, ctx, pool, user, email, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{
		Event: "site.info", Severity: SeverityInfo, Title: "Both channels",
	})
	if res.Enqueued != 2 {
		t.Fatalf("enqueued %d, want 2 (one per channel)", res.Enqueued)
	}

	var panelCalls, emailCalls atomic.Int32
	senders := map[string]Sender{
		ChannelInPanel: func(_ context.Context, _ Delivery) error { panelCalls.Add(1); return nil },
		ChannelEmail:   func(_ context.Context, _ Delivery) error { emailCalls.Add(1); return nil },
	}

	// A panel-only pass must touch only the panel delivery.
	if _, err := DeliverOnce(ctx, pool, senders, ClaimOptions{ChannelTypes: []string{ChannelInPanel}}); err != nil {
		t.Fatalf("panel pass: %v", err)
	}
	if panelCalls.Load() != 1 || emailCalls.Load() != 0 {
		t.Errorf("panel pass called panel=%d email=%d, want 1/0", panelCalls.Load(), emailCalls.Load())
	}
	// The email delivery is untouched and delivered by its own pass.
	if _, err := DeliverOnce(ctx, pool, senders, ClaimOptions{ChannelTypes: []string{ChannelEmail}}); err != nil {
		t.Fatalf("email pass: %v", err)
	}
	if emailCalls.Load() != 1 {
		t.Errorf("email pass called email=%d, want 1", emailCalls.Load())
	}
}

// Critical events are drained before info events when both are due, so an
// operator sees the fire before the paperwork.
func TestClaimPrioritizesCritical(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	mustPublish(t, ctx, pool, Event{Event: "a.info", Severity: SeverityInfo, Title: "info"})
	mustPublish(t, ctx, pool, Event{Event: "b.critical", Severity: SeverityCritical, Title: "crit"})

	var order []string
	var mu sync.Mutex
	senders := map[string]Sender{
		ChannelInPanel: func(_ context.Context, d Delivery) error {
			mu.Lock()
			order = append(order, d.Event)
			mu.Unlock()
			return nil
		},
	}
	// Claim one at a time so ordering is observable.
	if _, err := DeliverOnce(ctx, pool, senders, ClaimOptions{Limit: 1}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := DeliverOnce(ctx, pool, senders, ClaimOptions{Limit: 1}); err != nil {
		t.Fatalf("second: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "b.critical" || order[1] != "a.info" {
		t.Errorf("delivery order = %v, want [b.critical a.info]", order)
	}
}

// Two concurrent loops must not deliver the same row twice: SKIP LOCKED is the
// guarantee, and this is the test that would catch its removal.
func TestConcurrentDeliveryDoesNotDoubleSend(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	const total = 20
	for i := 0; i < total; i++ {
		mustPublish(t, ctx, pool, Event{
			Event: "site.info", Severity: SeverityInfo, Title: "Info",
			Payload: map[string]any{"i": i},
		})
	}

	var sends atomic.Int32
	senders := map[string]Sender{
		ChannelInPanel: func(_ context.Context, _ Delivery) error {
			sends.Add(1)
			return nil
		},
	}

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := DeliverOnce(ctx, pool, senders, ClaimOptions{Limit: 5})
				if err != nil {
					t.Errorf("DeliverOnce: %v", err)
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := sends.Load(); got != total {
		t.Errorf("sender called %d times for %d deliveries; want exactly %d (no double-send, none dropped)",
			got, total, total)
	}
	var delivered int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM notification_deliveries WHERE state='delivered'`).Scan(&delivered); err != nil {
		t.Fatalf("count delivered: %v", err)
	}
	if delivered != total {
		t.Errorf("delivered rows = %d, want %d", delivered, total)
	}
}

// MarkRead is idempotent and drives the unread badge; an unknown id is not-found.
func TestMarkReadAndUnreadCount(t *testing.T) {
	pool, ctx := setup(t)

	user := seedUser(t, ctx, pool, "user@example.test")
	channel := seedChannel(t, ctx, pool, ChannelInPanel, "panel", true)
	seedRoute(t, ctx, pool, user, channel, SeverityInfo)

	res := mustPublish(t, ctx, pool, Event{Event: "site.info", Severity: SeverityInfo, Title: "Info"})
	id := res.DeliveryIDs[0]
	senders := map[string]Sender{ChannelInPanel: func(_ context.Context, _ Delivery) error { return nil }}
	if _, err := DeliverOnce(ctx, pool, senders, ClaimOptions{}); err != nil {
		t.Fatalf("DeliverOnce: %v", err)
	}

	if n, err := UnreadCount(ctx, pool, user); err != nil {
		t.Fatalf("UnreadCount: %v", err)
	} else if n != 1 {
		t.Errorf("unread = %d, want 1", n)
	}

	if err := MarkRead(ctx, pool, id); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}
	// Idempotent: marking twice is not an error.
	if err := MarkRead(ctx, pool, id); err != nil {
		t.Fatalf("MarkRead twice: %v", err)
	}
	if n, err := UnreadCount(ctx, pool, user); err != nil {
		t.Fatalf("UnreadCount after read: %v", err)
	} else if n != 0 {
		t.Errorf("unread after read = %d, want 0", n)
	}

	// An unknown delivery is not-found, not a silent success.
	if err := MarkRead(ctx, pool, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("MarkRead of unknown id = %v, want ErrNotFound", err)
	}
}

func TestPublishValidation(t *testing.T) {
	pool, ctx := setup(t)
	cases := map[string]Event{
		"no event key":        {Severity: SeverityInfo, Title: "x"},
		"no title":            {Event: "e", Severity: SeverityInfo},
		"bad severity":        {Event: "e", Severity: "urgent", Title: "x"},
		"dedup without scope": {Event: "e", Severity: SeverityInfo, Title: "x", DedupKey: "k"},
	}
	for label, e := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := Publish(ctx, pool, e, PublishOptions{}); err == nil {
				t.Error("invalid event accepted")
			}
		})
	}
}

func TestSeverityRanking(t *testing.T) {
	if !AtLeast(SeverityCritical, SeverityWarning) {
		t.Error("critical should satisfy a warning minimum")
	}
	if AtLeast(SeverityInfo, SeverityWarning) {
		t.Error("info should not satisfy a warning minimum")
	}
	if !AtLeast(SeverityInfo, SeverityInfo) {
		t.Error("info should satisfy an info minimum")
	}
	// An unknown severity ranks lowest and satisfies nothing, so a typo cannot
	// escalate itself past a filter.
	if AtLeast("nonsense", SeverityInfo) {
		t.Error("an unknown severity should not satisfy any minimum")
	}
	if rank("nonsense") != 0 {
		t.Error("unknown severity should rank 0")
	}
}

func TestBackoffDelayGrowsAndCaps(t *testing.T) {
	if got := BackoffDelay(1); got != retryBaseDelay {
		t.Errorf("BackoffDelay(1) = %v, want %v", got, retryBaseDelay)
	}
	if got := BackoffDelay(3); got != 4*retryBaseDelay {
		t.Errorf("BackoffDelay(3) = %v, want %v", got, 4*retryBaseDelay)
	}
	if got := BackoffDelay(1000); got != retryMaxDelay {
		t.Errorf("BackoffDelay(1000) = %v, want cap %v", got, retryMaxDelay)
	}
	if got := BackoffDelay(0); got <= 0 {
		t.Errorf("BackoffDelay(0) = %v, want positive", got)
	}
}
