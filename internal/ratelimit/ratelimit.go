// Package ratelimit provides bounded, in-process request limiting.
//
// Purpose: blunt the login/recovery flows (SECURITY.md §11) and any other
// endpoint where unbounded attempts are the attack. This is deliberately a
// per-process limiter — it is NOT a distributed quota system. With multiple
// controller replicas the effective allowance is (limit × replicas), which is
// an acceptable trade for the authentication flows it guards, and it is
// documented rather than pretended.
//
// Memory is the reason this is not a naive map: a limiter keyed by client
// address is itself a denial-of-service target, because an attacker choosing
// keys can make the map grow without bound (AGENTS.md §12: bound every queue
// and cache). The store therefore has a hard entry ceiling and evicts.
package ratelimit

import (
	"errors"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter with a bounded key space.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	// order tracks insertion/refresh order for eviction. The oldest entry is
	// evicted when maxEntries is reached.
	order []string

	limit      float64 // tokens added per interval
	interval   time.Duration
	burst      float64 // bucket capacity
	maxEntries int
	now        func() time.Time
}

// Options configures a Limiter.
type Options struct {
	// Limit is the number of allowed events per Interval.
	Limit int
	// Interval is the refill window.
	Interval time.Duration
	// Burst is the bucket capacity: how many events may occur back-to-back.
	// Zero means Limit.
	Burst int
	// MaxEntries bounds the number of tracked keys. Zero means DefaultMaxEntries.
	MaxEntries int
}

// DefaultMaxEntries bounds limiter memory. 10k keys is comfortably more than
// the active client population of a small installation while keeping the
// worst-case footprint in the low megabytes.
const DefaultMaxEntries = 10_000

// ErrInvalidOptions is returned for a nonsensical configuration.
var ErrInvalidOptions = errors.New("ratelimit: invalid options")

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// New builds a Limiter.
func New(opts Options) (*Limiter, error) {
	if opts.Limit <= 0 {
		return nil, ErrInvalidOptions
	}
	if opts.Interval <= 0 {
		return nil, ErrInvalidOptions
	}
	burst := opts.Burst
	if burst <= 0 {
		burst = opts.Limit
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Limiter{
		buckets:    make(map[string]*bucket),
		order:      make([]string, 0, maxEntries),
		limit:      float64(opts.Limit),
		interval:   opts.Interval,
		burst:      float64(burst),
		maxEntries: maxEntries,
		now:        time.Now,
	}, nil
}

// Allow reports whether one event for key is permitted, and how long until the
// next one would be. A denied event does NOT consume a token, so a legitimate
// user is not pushed further back by the attacker's traffic.
func (l *Limiter) Allow(key string) (allowed bool, retryAfter time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.evictIfNeeded()
		b = &bucket{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
		l.order = append(l.order, key)
	}

	// Refill proportionally to elapsed time, capped at capacity.
	elapsed := now.Sub(b.lastSeen)
	if elapsed > 0 {
		b.tokens += (elapsed.Seconds() / l.interval.Seconds()) * l.limit
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}

	if b.tokens < 1 {
		// Time until one token accrues, rounded up so a retry is not rejected
		// on a rounding error.
		needed := 1 - b.tokens
		seconds := (needed / l.limit) * l.interval.Seconds()
		return false, time.Duration(seconds * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// Reset clears the state for one key. Used after a successful authentication so
// a user who mistyped a few times is not penalized once they succeed.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.buckets[key]; ok {
		delete(l.buckets, key)
		l.removeFromOrder(key)
	}
}

// Len reports the number of tracked keys (diagnostics and tests).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// evictIfNeeded drops the longest-tracked key when the ceiling is reached, so
// memory stays bounded no matter how many distinct keys an attacker invents.
// Eviction is FIFO by first observation, not by last activity: the point is a
// memory ceiling, and tracking recency here would add cost to the hot path.
// Callers must hold the lock.
func (l *Limiter) evictIfNeeded() {
	if len(l.buckets) < l.maxEntries {
		return
	}
	oldest := l.order[0]
	l.order = l.order[1:]
	delete(l.buckets, oldest)
}

// removeFromOrder drops a key from the eviction order. Callers must hold the
// lock. Linear scan: the order slice is only touched on Reset and eviction,
// never on the hot Allow path.
func (l *Limiter) removeFromOrder(key string) {
	for i, k := range l.order {
		if k == key {
			l.order = append(l.order[:i], l.order[i+1:]...)
			return
		}
	}
}
