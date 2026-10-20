package collector

// Bounded hand-off between a kernel collector's reader goroutine and Collect().
//
// Every platform's KernelCollector held the same thing: an `events []Telemetry`
// guarded by a mutex, appended to from the reader goroutine and set to nil by
// Collect(). That is unbounded by construction. The reader runs as fast as the
// kernel produces events; Collect() runs once per agent cycle. If a cycle is
// slow — a forensic upload, a rule reload, an ML inference, a stalled
// forwarder — the slice grows for as long as the stall lasts, and because each
// Telemetry carries command lines and paths the growth is in hundreds of bytes
// per event. There is no ceiling and no drop counter, so the first visible
// symptom is the agent being killed by the OOM killer, which is also the point
// at which it stops reporting.
//
// BoundedRing and EPSLimiter in budget.go were written for exactly this and had
// no callers outside their own tests. This file is the hand-off they were for:
// a fixed-capacity FIFO that drops the newest event when full and counts what
// it dropped, in front of an optional events-per-second ceiling.
//
// Dropping the newest rather than the oldest is deliberate. Under a burst the
// oldest events in the ring are the ones already correlated into whatever the
// detection layers are building; the newest are the tail of a flood that is
// very likely more of the same. Dropping the head would also mean every
// dropped event had already been paid for once.

import (
	"sync"

	"github.com/razatechofficial/edr/internal/config"
)

// defaultTelemetryQueueCapacity is used when performance.event_buffer_size is
// unset. It matches the shipped default for that key.
const defaultTelemetryQueueCapacity = 2048

// TelemetryQueue is the bounded queue a collector's reader pushes into and
// Collect() drains.
//
// Safe for one or more producers and one consumer. The ring has its own lock;
// the mutex here guards only the reusable drain buffer, so a producer never
// waits on a consumer that is copying a batch out.
type TelemetryQueue struct {
	ring  *BoundedRing[Telemetry]
	limit *EPSLimiter

	mu    sync.Mutex
	drain []Telemetry
}

// NewTelemetryQueue builds a queue sized from the agent's performance config.
//
// Capacity comes from performance.event_buffer_size, which until now was read
// by nothing on this path. The events-per-second ceiling comes from
// performance.max_events_per_second and defaults to 0, meaning no rate limit:
// a default EPS ceiling would silently discard kernel events on a busy host,
// and an EDR that quietly stops seeing things on exactly the hosts that are
// busiest is worse than one that reports memory pressure and drops with a
// counter. The ring's capacity is the safety net that always applies; the rate
// limiter is there for operators who would rather cap the agent's work than
// let it keep up.
func NewTelemetryQueue(cfg config.Config) *TelemetryQueue {
	capacity := cfg.Performance.EventBufferSize
	if capacity <= 0 {
		capacity = defaultTelemetryQueueCapacity
	}
	var limiter *EPSLimiter
	if eps := cfg.Performance.MaxEventsPerSecond; eps > 0 {
		// Burst is one second of ring capacity or the rate, whichever
		// is larger, so a short spike is absorbed rather than clipped.
		burst := float64(capacity)
		if float64(eps) > burst {
			burst = float64(eps)
		}
		limiter = NewEPSLimiter(float64(eps), burst)
	}
	return &TelemetryQueue{
		ring:  NewBoundedRing[Telemetry](capacity),
		limit: limiter,
	}
}

// Push enqueues one telemetry item, reporting whether it was kept.
//
// A false return is a drop that has already been counted, and the caller's
// only job is not to double-count it. Callers must not retry or buffer: the
// whole point is that there is no second queue behind this one.
func (q *TelemetryQueue) Push(t Telemetry) bool {
	if q == nil {
		return false
	}
	if q.limit != nil && !q.limit.Allow() {
		return false
	}
	return q.ring.TryPush(t)
}

// PushAll enqueues each item and returns how many were kept.
func (q *TelemetryQueue) PushAll(items []Telemetry) int {
	kept := 0
	for i := range items {
		if q.Push(items[i]) {
			kept++
		}
	}
	return kept
}

// Drain removes and returns everything queued.
//
// The returned slice is freshly allocated per call because Collect() hands it
// to the agent, which keeps it for the length of a process cycle; reusing one
// buffer would alias the batch the agent is still reading. The internal drain
// buffer is reused for the copy, so the only allocation per cycle is the
// batch itself, one per cycle rather than one per append as the unbounded
// slice did.
func (q *TelemetryQueue) Drain() []Telemetry {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	q.drain = q.ring.Pop(q.drain[:0], 0)
	if len(q.drain) == 0 {
		return nil
	}
	out := make([]Telemetry, len(q.drain))
	copy(out, q.drain)
	return out
}

// Len reports how many items are queued right now.
func (q *TelemetryQueue) Len() int {
	if q == nil {
		return 0
	}
	return q.ring.Len()
}

// Dropped reports how many items the ring refused plus how many the rate
// limiter refused, which is what an operator needs to know before trusting an
// absence of events.
func (q *TelemetryQueue) Dropped() uint64 {
	if q == nil {
		return 0
	}
	_, _, ringDropped := q.ring.Stats()
	var rateDropped uint64
	if q.limit != nil {
		_, rateDropped = q.limit.Stats()
	}
	return ringDropped + rateDropped
}

// HealthExtras returns the queue's counters for the collector health surface.
//
// Reported unconditionally, including when nothing has been dropped: a field
// that only appears once something is wrong is a field no dashboard has a
// panel for.
func (q *TelemetryQueue) HealthExtras(dst map[string]any) map[string]any {
	if dst == nil {
		dst = make(map[string]any, 6)
	}
	if q == nil {
		return dst
	}
	pushed, popped, dropped := q.ring.Stats()
	dst["event_queue_depth"] = q.ring.Len()
	dst["event_queue_capacity"] = q.ring.Cap()
	dst["event_queue_pushed"] = pushed
	dst["event_queue_popped"] = popped
	dst["event_queue_dropped_full"] = dropped
	if q.limit != nil {
		allowed, rejected := q.limit.Stats()
		dst["event_queue_eps_allowed"] = allowed
		dst["event_queue_dropped_eps"] = rejected
	}
	return dst
}
