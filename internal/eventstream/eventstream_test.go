package eventstream

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Publish assigns monotonic ids per topic and delivers to every subscriber.
func TestPublishAssignsMonotonicIDsPerTopic(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	sub, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	for i := 0; i < 3; i++ {
		if _, pubErr := b.Publish("jobs", "job.progress", []byte("{}")); pubErr != nil {
			t.Fatalf("Publish: %v", pubErr)
		}
	}
	for want := uint64(1); want <= 3; want++ {
		got := nextEvent(t, sub, time.Second)
		if got.ID != want {
			t.Errorf("event id = %d, want %d", got.ID, want)
		}
	}

	// A different topic has its own counter.
	if _, pubErr := b.Publish("incidents", "incident.new", []byte("{}")); pubErr != nil {
		t.Fatalf("Publish other topic: %v", pubErr)
	}
	other, err := b.Subscribe("incidents", 0)
	if err != nil {
		t.Fatalf("Subscribe incidents: %v", err)
	}
	defer other.Close()
	if _, pubErr := b.Publish("incidents", "incident.new", []byte("{}")); pubErr != nil {
		t.Fatalf("Publish: %v", pubErr)
	}
	if got := nextEvent(t, other, time.Second); got.ID != 2 {
		t.Errorf("incidents topic id = %d, want 2 (per-topic counter)", got.ID)
	}
}

// A slow subscriber must not block the publisher: it is marked lagged and the
// publish returns promptly. This is the property that stops one stalled browser
// tab from freezing every other subscriber.
func TestSlowSubscriberIsLaggedNotBlocking(t *testing.T) {
	b := New(Options{SubscriptionBuffer: 2})
	defer b.Close()

	sub, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	// Overflow the buffer without reading anything.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5; i++ {
			if _, err := b.Publish("jobs", "job.progress", []byte("{}")); err != nil {
				t.Errorf("Publish %d: %v", i, err)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber buffer")
	}

	if !sub.Lagged() {
		t.Error("an overflowing subscriber was not marked lagged")
	}
}

// Resume from a last-seen id replays the gap, so a reconnecting client does not
// silently miss what happened while it was away.
func TestSubscribeResumesFromSinceID(t *testing.T) {
	b := New(Options{ReplayBuffer: 10})
	defer b.Close()

	for i := 0; i < 4; i++ {
		if _, err := b.Publish("jobs", "job.progress", []byte("{}")); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	// Reconnect having seen id 2; expect 3 and 4.
	sub, err := b.Subscribe("jobs", 2)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	if sub.Lagged() {
		t.Error("a fully-covered resume reported itself lagged")
	}
	for _, want := range []uint64{3, 4} {
		got := nextEvent(t, sub, time.Second)
		if got.ID != want {
			t.Errorf("replayed id = %d, want %d", got.ID, want)
		}
	}
}

// A client further behind than the replay buffer reaches must be told it missed
// events, rather than silently resuming with a hole in it.
func TestSubscribeBeyondReplayBufferIsLagged(t *testing.T) {
	b := New(Options{ReplayBuffer: 2})
	defer b.Close()

	for i := 0; i < 6; i++ {
		if _, err := b.Publish("jobs", "job.progress", []byte("{}")); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	// Replay holds ids 5 and 6. Asking to resume after 1 is unreachable.
	sub, err := b.Subscribe("jobs", 1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	if !sub.Lagged() {
		t.Fatal("a resume beyond the replay buffer was not marked lagged")
	}
	// The reachable tail is still delivered.
	if got := nextEvent(t, sub, time.Second); got.ID != 5 {
		t.Errorf("first replayed id = %d, want 5", got.ID)
	}
}

// Run emits a lagged frame first when the subscription started behind, so a
// client cannot render good events before learning it missed some.
func TestRunReportsLaggedBeforeOtherEvents(t *testing.T) {
	b := New(Options{ReplayBuffer: 1, Heartbeat: time.Hour})
	defer b.Close()

	for i := 0; i < 4; i++ {
		if _, err := b.Publish("jobs", "job.progress", []byte("{}")); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	sub, err := b.Subscribe("jobs", 1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	ctx, cancel := context.WithCancel(context.Background())
	frames := make(chan string, 8)
	go func() {
		_ = sub.Run(ctx, func(frame string) error {
			select {
			case frames <- frame:
			default:
			}
			return nil
		})
	}()
	defer cancel()

	first := receiveFrame(t, frames, time.Second)
	if !strings.Contains(first, "event: lagged") {
		t.Errorf("first frame = %q, want the lagged signal", first)
	}
}

// Close ends the subscription and Run returns, so a disconnected client cannot
// leave a goroutine parked forever.
func TestCloseEndsRun(t *testing.T) {
	b := New(Options{Heartbeat: time.Hour})
	defer b.Close()

	sub, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_ = sub.Run(context.Background(), func(string) error { return nil })
	}()

	sub.Close()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
	// Idempotent, and safe to call after the broker has already removed it.
	sub.Close()
	if b.SubscriberCount("jobs") != 0 {
		t.Errorf("subscriber count = %d, want 0 after Close", b.SubscriberCount("jobs"))
	}
}

// A write error (client gone) ends Run and does not retry: the only writer that
// matters is gone.
func TestRunStopsOnWriteError(t *testing.T) {
	b := New(Options{Heartbeat: time.Hour})
	defer b.Close()

	sub, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	wantErr := errors.New("client disconnected")
	ended := make(chan error, 1)
	go func() {
		ended <- sub.Run(context.Background(), func(string) error { return wantErr })
	}()

	// Delivering an event triggers the write and therefore the error.
	if _, err := b.Publish("jobs", "job.progress", []byte("{}")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case got := <-ended:
		if !errors.Is(got, wantErr) {
			t.Errorf("Run returned %v, want %v", got, wantErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on a write error")
	}
}

// Context cancellation ends the stream, which is what happens when a browser tab
// is closed.
func TestRunStopsOnContextCancel(t *testing.T) {
	b := New(Options{Heartbeat: time.Hour})
	defer b.Close()

	sub, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_ = sub.Run(ctx, func(string) error { return nil })
	}()

	cancel()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

// The subscriber cap exists so a client looping connections cannot exhaust
// server resources; the cap must refuse rather than grow without bound.
func TestSubscriberLimitIsEnforced(t *testing.T) {
	b := New(Options{MaxSubscribers: 2})
	defer b.Close()

	first, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	defer first.Close()
	second, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("second Subscribe: %v", err)
	}
	defer second.Close()

	if _, subErr := b.Subscribe("jobs", 0); !errors.Is(subErr, ErrTooManySubscribers) {
		t.Errorf("third Subscribe = %v, want ErrTooManySubscribers", subErr)
	}

	// Releasing one slot lets a new subscriber in, so the limit does not
	// permanently wedge a topic after clients disconnect.
	first.Close()
	third, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe after Close: %v", err)
	}
	third.Close()
}

// Closing the broker ends every subscription and refuses new ones.
func TestBrokerCloseEndsAllSubscriptions(t *testing.T) {
	b := New(Options{Heartbeat: time.Hour})

	sub, err := b.Subscribe("jobs", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_ = sub.Run(context.Background(), func(string) error { return nil })
	}()

	b.Close()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after broker Close")
	}
	if _, err := b.Subscribe("jobs", 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Subscribe after Close = %v, want ErrClosed", err)
	}
	if _, err := b.Publish("jobs", "x", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Publish after Close = %v, want ErrClosed", err)
	}
	// Idempotent.
	b.Close()
}

// Zero or negative options must fall back to usable defaults: a zero-capacity
// buffer would silently drop every event, which is worse than refusing to start.
func TestNewAppliesDefaults(t *testing.T) {
	b := New(Options{})
	defer b.Close()
	if b.Heartbeat() != DefaultHeartbeat {
		t.Errorf("heartbeat = %v, want %v", b.Heartbeat(), DefaultHeartbeat)
	}
	if b.subBuffer != DefaultSubscriptionBuffer {
		t.Errorf("sub buffer = %d, want %d", b.subBuffer, DefaultSubscriptionBuffer)
	}
	if b.replayLimit != DefaultReplayBuffer {
		t.Errorf("replay limit = %d, want %d", b.replayLimit, DefaultReplayBuffer)
	}
	if b.maxSubs != DefaultMaxSubscribers {
		t.Errorf("max subscribers = %d, want %d", b.maxSubs, DefaultMaxSubscribers)
	}

	// Negative values are replaced too.
	b2 := New(Options{SubscriptionBuffer: -1, ReplayBuffer: -5, Heartbeat: -time.Second, MaxSubscribers: 0})
	defer b2.Close()
	if b2.subBuffer != DefaultSubscriptionBuffer || b2.maxSubs != DefaultMaxSubscribers {
		t.Error("negative options were not replaced with defaults")
	}
}

// PublishJSON is the only publish path call sites should use, so it must reject
// both a bad topic and an unmarshalable payload rather than emit a stream the UI
// cannot parse.
func TestPublishJSONValidatesTopicAndPayload(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	if _, err := b.PublishJSON(context.Background(), "bad topic!", "x", map[string]string{"a": "b"}); err == nil {
		t.Error("PublishJSON accepted an invalid topic")
	}
	if _, err := b.PublishJSON(context.Background(), "jobs", "x", make(chan int)); err == nil {
		t.Error("PublishJSON accepted an unmarshalable payload")
	}
	if _, err := b.PublishJSON(context.Background(), "jobs", "x", map[string]string{"a": "b"}); err != nil {
		t.Errorf("PublishJSON of a valid payload: %v", err)
	}

	// A canceled context is refused, so a caller that has already given up does
	// not leave a published event behind.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.PublishJSON(ctx, "jobs", "x", map[string]string{"a": "b"}); err == nil {
		t.Error("PublishJSON accepted a canceled context")
	}
}

func TestTopicHelpers(t *testing.T) {
	if got := UserTopic("abc"); got != "user:abc" {
		t.Errorf("UserTopic = %q, want user:abc", got)
	}
}

func TestValidTopic(t *testing.T) {
	valid := []string{"jobs", "incidents", "user:abc-123", "server.web_1"}
	for _, topic := range valid {
		if !validTopic(topic) {
			t.Errorf("validTopic(%q) = false, want true", topic)
		}
	}
	invalid := []string{"", "a b", "user:../../etc", "x\ny", "ünicode", string(make([]byte, 200))}
	for _, topic := range invalid {
		if validTopic(topic) {
			t.Errorf("validTopic(%q) = true, want false", topic)
		}
	}
}

func TestFrameFormatting(t *testing.T) {
	// The SSE wire format is fixed; these pin the exact bytes a browser parses.
	if got := eventFrame(Event{ID: 7, Type: "job.progress", Data: []byte(`{"a":1}`)}); got != "id: 7\nevent: job.progress\ndata: {\"a\":1}\n\n" {
		t.Errorf("eventFrame = %q", got)
	}
	// An empty type falls back to "message", the SSE default.
	if got := eventFrame(Event{ID: 1, Data: []byte("{}")}); got != "id: 1\nevent: message\ndata: {}\n\n" {
		t.Errorf("eventFrame with no type = %q", got)
	}
	if got := heartbeatFrame(3); got != ": heartbeat 3\n\n" {
		t.Errorf("heartbeatFrame = %q", got)
	}
	if got := laggedFrame(9); got != "id: 9\nevent: lagged\ndata: {}\n\n" {
		t.Errorf("laggedFrame = %q", got)
	}
}

func nextEvent(t *testing.T, sub *Subscription, timeout time.Duration) Event {
	t.Helper()
	select {
	case ev, ok := <-sub.Events():
		if !ok {
			t.Fatal("subscription channel closed while waiting for an event")
		}
		return ev
	case <-time.After(timeout):
		t.Fatal("timed out waiting for an event")
		return Event{}
	}
}

func receiveFrame(t *testing.T, frames <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case f := <-frames:
		return f
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a frame")
		return ""
	}
}
