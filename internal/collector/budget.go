package collector

import (
	"sync"
	"sync/atomic"
	"time"
)

// EPSLimiter is a thread-safe token-bucket rate limiter denominated in events
// per second. Allow returns true if the caller may emit the event; otherwise
// the drop is counted and the caller must not emit. It is the only sanctioned
// rate limiter on the monitoring hot path.
type EPSLimiter struct {
	mu       sync.Mutex // guards: tokens, last
	rate     float64    // tokens per second
	burst    float64    // bucket capacity
	tokens   float64
	last     time.Time
	now      func() time.Time
	allowed  atomic.Uint64
	rejected atomic.Uint64
}

// NewEPSLimiter constructs a limiter at ratePerSec EPS with the given burst
// capacity. ratePerSec <= 0 disables limiting (Allow always returns true);
// burst <= 0 defaults to ratePerSec.
func NewEPSLimiter(ratePerSec, burst float64) *EPSLimiter {
	if burst <= 0 {
		burst = ratePerSec
	}
	if burst < 1 && ratePerSec > 0 {
		burst = 1
	}
	return &EPSLimiter{
		rate:   ratePerSec,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
		now:    time.Now,
	}
}

// Allow consumes one token. With ratePerSec <= 0 it always returns true.
func (l *EPSLimiter) Allow() bool { return l.AllowN(1) }

// AllowN consumes n tokens.
func (l *EPSLimiter) AllowN(n float64) bool {
	if l == nil || l.rate <= 0 {
		l.allowed.Add(uint64(n))
		return true
	}
	l.mu.Lock()
	now := l.now()
	elapsed := now.Sub(l.last).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}
	if l.tokens < n {
		l.mu.Unlock()
		l.rejected.Add(uint64(n))
		return false
	}
	l.tokens -= n
	l.mu.Unlock()
	l.allowed.Add(uint64(n))
	return true
}

// Stats returns lifetime allowed and rejected counts.
func (l *EPSLimiter) Stats() (allowed, rejected uint64) {
	if l == nil {
		return 0, 0
	}
	return l.allowed.Load(), l.rejected.Load()
}

// BoundedRing is a fixed-size FIFO. TryPush returns false (and counts the
// drop) when full; this is the only allowed pattern for collector→pipeline
// handoff so the steady-state has zero unbounded slice growth.
type BoundedRing[T any] struct {
	mu      sync.Mutex // guards: buf, head, tail, size
	buf     []T
	head    int // next pop
	tail    int // next push
	size    int
	cap     int
	pushed  atomic.Uint64
	popped  atomic.Uint64
	dropped atomic.Uint64
}

// NewBoundedRing constructs a ring with the given capacity. cap <= 0 defaults
// to 1024.
func NewBoundedRing[T any](capacity int) *BoundedRing[T] {
	if capacity <= 0 {
		capacity = 1024
	}
	return &BoundedRing[T]{buf: make([]T, capacity), cap: capacity}
}

// TryPush enqueues v if space is available. Returns true on success.
func (r *BoundedRing[T]) TryPush(v T) bool {
	r.mu.Lock()
	if r.size == r.cap {
		r.mu.Unlock()
		r.dropped.Add(1)
		return false
	}
	r.buf[r.tail] = v
	r.tail = (r.tail + 1) % r.cap
	r.size++
	r.mu.Unlock()
	r.pushed.Add(1)
	return true
}

// Pop dequeues at most max items into dst (a reusable slice supplied by the
// caller for zero-alloc draining) and returns it.
func (r *BoundedRing[T]) Pop(dst []T, max int) []T {
	if max <= 0 {
		max = r.cap
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < max && r.size > 0; i++ {
		dst = append(dst, r.buf[r.head])
		var zero T
		r.buf[r.head] = zero // release reference for GC
		r.head = (r.head + 1) % r.cap
		r.size--
		r.popped.Add(1)
	}
	return dst
}

// Len returns the current size.
func (r *BoundedRing[T]) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Cap returns the configured capacity.
func (r *BoundedRing[T]) Cap() int { return r.cap }

// Stats returns lifetime push/pop/drop counters.
func (r *BoundedRing[T]) Stats() (pushed, popped, dropped uint64) {
	return r.pushed.Load(), r.popped.Load(), r.dropped.Load()
}
