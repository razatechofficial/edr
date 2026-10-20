package collector

// Tests for the bounded collector→pipeline hand-off.
//
// The property that matters is the one the old `events []Telemetry` did not
// have: a ceiling. A producer that outruns the consumer has to stop consuming
// memory at some point, that point has to be configurable, and what was lost
// has to be countable — otherwise the first symptom of a slow process cycle is
// the OOM killer, and the agent that was supposed to report the incident is
// the thing that died during it.

import (
	"sync"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// marker builds a Telemetry identifiable by PID, so FIFO order and aliasing
// can be asserted without caring what else a Telemetry carries.
func marker(pid int) Telemetry {
	return Telemetry{Process: &schema.ProcessEvent{PID: pid}}
}

func queueCfg(capacity, eps int) config.Config {
	var cfg config.Config
	cfg.Performance.EventBufferSize = capacity
	cfg.Performance.MaxEventsPerSecond = eps
	return cfg
}

// TestTelemetryQueueIsBounded is the whole point: a producer that outruns the
// consumer stops at the ceiling instead of growing.
func TestTelemetryQueueIsBounded(t *testing.T) {
	t.Parallel()
	q := NewTelemetryQueue(queueCfg(8, 0))

	kept := 0
	for i := 0; i < 1000; i++ {
		if q.Push(Telemetry{}) {
			kept++
		}
	}
	if kept != 8 {
		t.Errorf("kept %d of 1000 pushes into a capacity-8 queue, want 8", kept)
	}
	if got := q.Len(); got != 8 {
		t.Errorf("Len() = %d, want 8", got)
	}
	if got := q.Dropped(); got != 992 {
		t.Errorf("Dropped() = %d, want 992; a drop nobody counted is a drop nobody can see", got)
	}
}

// TestTelemetryQueueDrainIsFIFOAndEmpties asserts a drain returns everything
// in order and leaves room for the next burst.
func TestTelemetryQueueDrainIsFIFOAndEmpties(t *testing.T) {
	t.Parallel()
	q := NewTelemetryQueue(queueCfg(4, 0))

	for i := 0; i < 4; i++ {
		if !q.Push(marker(i)) {
			t.Fatalf("push %d refused with room left", i)
		}
	}
	batch := q.Drain()
	if len(batch) != 4 {
		t.Fatalf("drained %d, want 4", len(batch))
	}
	for i := range batch {
		if batch[i].Process == nil || batch[i].Process.PID != i {
			t.Errorf("batch[%d] is %+v, want the item pushed %dth: the queue is FIFO so correlation order survives it", i, batch[i].Process, i)
		}
	}
	if q.Len() != 0 {
		t.Errorf("Len() = %d after a full drain, want 0", q.Len())
	}
	if q.Drain() != nil {
		t.Error("draining an empty queue returned a non-nil batch; Collect would hand the agent an empty slice every idle cycle")
	}

	// A drained queue takes a fresh burst: the ring wraps rather than
	// filling up permanently.
	for i := 0; i < 4; i++ {
		if !q.Push(Telemetry{}) {
			t.Fatalf("push %d refused after a drain; the ring is not wrapping", i)
		}
	}
}

// TestTelemetryQueueDrainDoesNotAliasItsBuffer asserts a drained batch is not
// overwritten by the next drain.
//
// The queue reuses an internal buffer for the copy out of the ring. If it
// returned that buffer the agent would be reading a batch that the next cycle
// rewrites underneath it, which is the kind of bug that shows up as events
// attributed to the wrong process rather than as a crash.
func TestTelemetryQueueDrainDoesNotAliasItsBuffer(t *testing.T) {
	t.Parallel()
	q := NewTelemetryQueue(queueCfg(4, 0))

	q.Push(marker(1))
	first := q.Drain()
	q.Push(marker(2))
	q.Drain()

	if first[0].Process == nil || first[0].Process.PID != 1 {
		t.Errorf("the first batch now reads %+v; the second drain overwrote a batch the caller still held", first[0].Process)
	}
}

// TestTelemetryQueueRateLimitIsOptOut asserts the EPS ceiling is off unless
// configured, and bites when it is.
//
// Off by default is deliberate. A default rate ceiling discards kernel events
// on the busiest hosts, which is where an EDR can least afford to stop seeing
// things; the ring's capacity is the bound that always applies.
func TestTelemetryQueueRateLimitIsOptOut(t *testing.T) {
	t.Parallel()

	unlimited := NewTelemetryQueue(queueCfg(1024, 0))
	if unlimited.limit != nil {
		t.Error("a queue built with max_events_per_second unset has a rate limiter; the ceiling must be opt-in")
	}
	for i := 0; i < 1024; i++ {
		if !unlimited.Push(Telemetry{}) {
			t.Fatalf("push %d refused with no rate limit and room in the ring", i)
		}
	}

	// A rate of 1 with a burst clamped by the small capacity: the burst is
	// max(capacity, rate), so capacity 4 gives a burst of 4.
	limited := NewTelemetryQueue(queueCfg(4, 1))
	if limited.limit == nil {
		t.Fatal("max_events_per_second was set and no limiter was built")
	}
	kept := 0
	for i := 0; i < 50; i++ {
		if limited.Push(Telemetry{}) {
			kept++
		}
	}
	if kept > 5 {
		t.Errorf("kept %d of 50 pushes at 1 EPS with a burst of 4; the rate limiter is not being consulted", kept)
	}
	if limited.Dropped() == 0 {
		t.Error("rate-limited drops are not counted")
	}
}

// TestTelemetryQueueConcurrentProducers exercises the real shape: several
// producer goroutines and one consumer, which is what darwin's collector does
// with its ESF loop, its network-extension reader and its FSEvents fallback.
func TestTelemetryQueueConcurrentProducers(t *testing.T) {
	t.Parallel()
	q := NewTelemetryQueue(queueCfg(64, 0))

	const producers = 8
	const each = 200
	var wg sync.WaitGroup
	wg.Add(producers)
	for p := 0; p < producers; p++ {
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				q.Push(Telemetry{})
			}
		}()
	}

	drained := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			batch := q.Drain()
			drained += len(batch)
			select {
			case <-done:
				return
			default:
			}
			if drained >= producers*each {
				return
			}
			if batch == nil {
				// Give the producers a turn rather than
				// spinning; this is a test, not the hot path.
				return
			}
		}
	}()
	wg.Wait()
	<-done

	// The exact split between drained and dropped depends on scheduling,
	// which is the point: whatever it is, the two must account for every
	// push and the queue must never have held more than its capacity.
	if total := uint64(drained) + q.Dropped() + uint64(q.Len()); total != producers*each {
		t.Errorf("drained %d + dropped %d + queued %d = %d, want %d: an event went missing without being counted",
			drained, q.Dropped(), q.Len(), total, producers*each)
	}
	if q.Len() > q.ring.Cap() {
		t.Errorf("queue holds %d items with a capacity of %d", q.Len(), q.ring.Cap())
	}
}

// TestTelemetryQueueNilIsSafe asserts the zero value does not panic.
//
// Collectors on platforms without a kernel tier return nil collectors, and a
// panic in Collect() takes the agent's whole process cycle down with it.
func TestTelemetryQueueNilIsSafe(t *testing.T) {
	t.Parallel()
	var q *TelemetryQueue
	if q.Push(Telemetry{}) {
		t.Error("a nil queue accepted a push")
	}
	if q.PushAll([]Telemetry{{}, {}}) != 0 {
		t.Error("a nil queue accepted a batch")
	}
	if q.Drain() != nil || q.Len() != 0 || q.Dropped() != 0 {
		t.Error("a nil queue reported state")
	}
	if extras := q.HealthExtras(nil); extras == nil {
		t.Error("HealthExtras(nil) on a nil queue returned nil; the health surface expects a map")
	}
}

// TestTelemetryQueueHealthExtrasAlwaysReports asserts the counters appear even
// when nothing has gone wrong.
//
// A field that only shows up once something is broken is a field no dashboard
// has a panel for, so nobody notices the first time it appears.
func TestTelemetryQueueHealthExtrasAlwaysReports(t *testing.T) {
	t.Parallel()
	q := NewTelemetryQueue(queueCfg(16, 0))
	q.Push(Telemetry{})

	extras := q.HealthExtras(map[string]any{"existing": 1})
	for _, key := range []string{
		"existing",
		"event_queue_depth",
		"event_queue_capacity",
		"event_queue_pushed",
		"event_queue_popped",
		"event_queue_dropped_full",
	} {
		if _, ok := extras[key]; !ok {
			t.Errorf("HealthExtras is missing %q", key)
		}
	}
	if _, ok := extras["event_queue_dropped_eps"]; ok {
		t.Error("the EPS counters are reported with no rate limiter configured, which implies a ceiling that is not there")
	}
}

// BenchmarkTelemetryQueuePush measures the hot path: one push per kernel
// event, on the collector's reader goroutine.
func BenchmarkTelemetryQueuePush(b *testing.B) {
	q := NewTelemetryQueue(queueCfg(1024, 0))
	t := marker(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !q.Push(t) {
			// Full is the steady state at this ratio; drain so the
			// benchmark keeps measuring the push and not the drop.
			q.Drain()
		}
	}
}

// TestTelemetryQueuePushDoesNotAllocate is the benchmark's assertion.
//
// Push runs once per kernel event. The unbounded slice it replaced allocated
// on every growth; the ring must not allocate at all, or the fix would have
// traded unbounded memory for unbounded garbage.
func TestTelemetryQueuePushDoesNotAllocate(t *testing.T) {
	q := NewTelemetryQueue(queueCfg(1024, 0))
	tel := marker(1)
	q.Push(tel)
	q.Drain()

	if n := testing.AllocsPerRun(500, func() {
		if !q.Push(tel) {
			q.Drain()
		}
	}); n != 0 {
		t.Errorf("Push allocates %.1f objects per call; it runs once per kernel event", n)
	}
}
