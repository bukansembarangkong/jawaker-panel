package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

// newTestLimiter builds a limiter with a controllable clock so refill behavior
// is deterministic rather than timing-dependent.
func newTestLimiter(t *testing.T, opts Options) (*Limiter, *time.Time) {
	t.Helper()
	l, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	clock := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	return l, &clock
}

func TestAllowPermitsUpToBurstThenDenies(t *testing.T) {
	l, _ := newTestLimiter(t, Options{Limit: 5, Interval: time.Minute, Burst: 3})

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("1.2.3.4"); !ok {
			t.Fatalf("attempt %d denied inside the burst", i+1)
		}
	}
	ok, retryAfter := l.Allow("1.2.3.4")
	if ok {
		t.Fatal("attempt beyond the burst allowed")
	}
	if retryAfter <= 0 {
		t.Error("denied attempt reported no retry delay")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(t, Options{Limit: 1, Interval: time.Minute, Burst: 1})

	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first key denied")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("second attempt on the same key allowed")
	}
	// One client exhausting its bucket must not affect another.
	if ok, _ := l.Allow("b"); !ok {
		t.Error("unrelated key denied")
	}
}

func TestDeniedAttemptDoesNotConsumeToken(t *testing.T) {
	l, clock := newTestLimiter(t, Options{Limit: 60, Interval: time.Minute, Burst: 1})

	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("first attempt denied")
	}
	// Spam denials: these must not push the recovery time further out.
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow("k"); ok {
			t.Fatalf("attempt %d allowed inside an exhausted bucket", i)
		}
	}

	// A full minute refills exactly one token regardless of the spam above.
	*clock = clock.Add(time.Minute)
	if ok, _ := l.Allow("k"); !ok {
		t.Error("token did not accrue after the refill interval; denials consumed tokens")
	}
}

func TestRefillIsProportionalToElapsedTime(t *testing.T) {
	// One token per minute: half the interval accrues half a token, which is
	// the boundary this test is about.
	l, clock := newTestLimiter(t, Options{Limit: 1, Interval: time.Minute, Burst: 1})

	l.Allow("k") // drains the only token

	// Half the interval yields half a token: not enough to serve a request.
	*clock = clock.Add(30 * time.Second)
	if ok, _ := l.Allow("k"); ok {
		t.Error("allowed with only half a token accrued")
	}

	// Another 30s completes one token.
	*clock = clock.Add(30 * time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Error("denied after a full interval of accrual")
	}
}

func TestTokensAreCappedAtBurst(t *testing.T) {
	l, clock := newTestLimiter(t, Options{Limit: 5, Interval: time.Minute, Burst: 2})

	l.Allow("k")
	l.Allow("k")

	// A long idle period must not bank unlimited tokens; a client that has been
	// quiet for a week should not be able to burst a week's allowance.
	*clock = clock.Add(7 * 24 * time.Hour)

	allowed := 0
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow("k"); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d after a long idle period, want the burst cap of 2", allowed)
	}
}

func TestResetClearsState(t *testing.T) {
	l, _ := newTestLimiter(t, Options{Limit: 1, Interval: time.Minute, Burst: 1})

	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("bucket not exhausted")
	}
	l.Reset("k")
	if ok, _ := l.Allow("k"); !ok {
		t.Error("Reset did not clear the bucket")
	}
	if l.Len() != 1 {
		t.Errorf("Len = %d, want 1", l.Len())
	}

	// Resetting an unknown key is a no-op, not a leak.
	l.Reset("never-seen")
	if l.Len() != 1 {
		t.Errorf("Len = %d after resetting an unknown key, want 1", l.Len())
	}
}

// The entry ceiling is the whole reason this is not a plain map: an attacker
// choosing keys must not be able to grow memory without bound.
func TestMemoryIsBoundedUnderKeyFlood(t *testing.T) {
	const maxEntries = 64
	l, _ := newTestLimiter(t, Options{Limit: 1, Interval: time.Minute, Burst: 1, MaxEntries: maxEntries})

	for i := 0; i < maxEntries*20; i++ {
		l.Allow(string(rune('a'+i%26)) + "-" + strconv.Itoa(i))
	}

	if l.Len() > maxEntries {
		t.Errorf("tracked keys = %d, want at most %d", l.Len(), maxEntries)
	}
	// The eviction order must not grow separately from the map, or the bound
	// would only cover half the memory.
	if len(l.order) != l.Len() {
		t.Errorf("order len = %d, map len = %d; they must stay in step",
			len(l.order), l.Len())
	}
}

// Evicting the oldest key must not leave a stale entry in the order slice, or
// a later eviction could delete a key twice and silently shrink the effective
// ceiling.
func TestEvictionKeepsOrderAndMapInStep(t *testing.T) {
	const maxEntries = 4
	l, _ := newTestLimiter(t, Options{Limit: 1, Interval: time.Minute, Burst: 1, MaxEntries: maxEntries})

	for i := 0; i < 100; i++ {
		l.Allow(strconv.Itoa(i))
		if len(l.order) != l.Len() {
			t.Fatalf("iteration %d: order len = %d, map len = %d", i, len(l.order), l.Len())
		}
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	cases := map[string]Options{
		"zero limit":      {Limit: 0, Interval: time.Minute},
		"negative limit":  {Limit: -1, Interval: time.Minute},
		"zero interval":   {Limit: 1, Interval: 0},
		"negative window": {Limit: 1, Interval: -time.Second},
	}
	for label, opts := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := New(opts); err == nil {
				t.Error("invalid options accepted")
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	l, err := New(Options{Limit: 10, Interval: time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Burst defaults to the limit so one interval's allowance may be spent at
	// once; MaxEntries defaults to the package ceiling so memory is bounded even
	// when the caller does not think about it.
	if l.burst != 10 {
		t.Errorf("default burst = %v, want 10", l.burst)
	}
	if l.maxEntries != DefaultMaxEntries {
		t.Errorf("default max entries = %d, want %d", l.maxEntries, DefaultMaxEntries)
	}
}
