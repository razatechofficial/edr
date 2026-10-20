package detection

// Tests for the resource governor and for its wiring into the engine.
//
// The governor shipped with no tests and no callers: a monitor loop that
// sampled CPU and memory into atomics nothing read, a Gate() nothing called,
// and a config field (performance.max_cpu_percent) that was validated,
// defaulted and written into every shipped config without reaching any code.
// Wiring it to Evaluate makes it the first thing every event meets, so its
// behaviour under pressure needs pinning down — in particular that it sheds a
// bounded fraction rather than going blind, and that it costs nothing when
// there is no pressure.

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testGovernor(t *testing.T, cfg GovernorConfig) *ResourceGovernor {
	t.Helper()
	return NewResourceGovernor(cfg, zap.NewNop())
}

// TestGovernorAdmitsWhenUnderBudget is the common case: no pressure, nothing
// shed, nothing slept on.
func TestGovernorAdmitsWhenUnderBudget(t *testing.T) {
	t.Parallel()
	g := testGovernor(t, DefaultGovernorConfig())

	for i := 0; i < 1000; i++ {
		if !g.Gate() {
			t.Fatalf("event %d shed with no CPU, memory or queue pressure", i)
		}
	}
	st := g.Stats()
	if st.EventsAdmitted != 1000 {
		t.Errorf("admitted = %d, want 1000", st.EventsAdmitted)
	}
	if st.EventsShed != 0 {
		t.Errorf("shed = %d, want 0", st.EventsShed)
	}
	if st.ThrottleCount != 0 {
		t.Errorf("throttled %d times with no CPU pressure; the throttle must not fire on an idle agent", st.ThrottleCount)
	}
}

// TestGovernorShedsASampleNotEverything asserts the queue-pressure path keeps
// one event in ShedSampleEvery.
//
// Dropping all of them is the behaviour this replaced. It makes the agent
// blind precisely when something is generating enough events to fill the
// queue, which is when being blind costs the most.
func TestGovernorShedsASampleNotEverything(t *testing.T) {
	t.Parallel()
	cfg := DefaultGovernorConfig()
	cfg.QueueHighWatermark = 10
	cfg.QueueLowWatermark = 5
	cfg.ShedSampleEvery = 4
	g := testGovernor(t, cfg)

	g.SetQueueDepth(100)
	const n = 400
	admitted := 0
	for i := 0; i < n; i++ {
		if g.Gate() {
			admitted++
		}
	}

	want := n / int(cfg.ShedSampleEvery)
	if admitted != want {
		t.Errorf("admitted %d of %d while shedding, want exactly one in %d (%d)", admitted, n, cfg.ShedSampleEvery, want)
	}
	st := g.Stats()
	if !st.Shedding {
		t.Error("Stats().Shedding is false while the queue is above the high watermark")
	}
	if st.EventsSampled != uint64(want) {
		t.Errorf("EventsSampled = %d, want %d: the kept events must be countable separately so nobody reads the sample as the whole", st.EventsSampled, want)
	}
	if st.EventsShed != uint64(n-want) {
		t.Errorf("EventsShed = %d, want %d", st.EventsShed, n-want)
	}

	// Falling below the low watermark resumes, and resuming is not
	// hysteresis-free: a depth between the two watermarks must not resume.
	g.SetQueueDepth(8)
	_ = g.Gate()
	if !g.Stats().Shedding {
		t.Error("resumed at a depth between the low and high watermarks; the hysteresis band exists to stop it flapping")
	}
	g.SetQueueDepth(1)
	if !g.Gate() {
		t.Error("still shedding below the low watermark")
	}
	if g.Stats().Shedding {
		t.Error("Stats().Shedding is still true after the queue drained below the low watermark")
	}
}

// TestGovernorShedsOnMemoryBudget asserts the RSS ceiling sheds too, and by
// the same sampled rule.
func TestGovernorShedsOnMemoryBudget(t *testing.T) {
	t.Parallel()
	cfg := DefaultGovernorConfig()
	cfg.ShedSampleEvery = 2
	g := testGovernor(t, cfg)

	g.memBytes.Store(cfg.MaxMemoryBytes + 1)
	admitted := 0
	for i := 0; i < 100; i++ {
		if g.Gate() {
			admitted++
		}
	}
	if admitted != 50 {
		t.Errorf("admitted %d of 100 over the memory budget, want 50 (one in 2)", admitted)
	}

	g.memBytes.Store(cfg.MaxMemoryBytes - 1)
	if !g.Gate() {
		t.Error("still shedding once memory is back under budget")
	}
}

// TestGovernorThrottleIsAmortised asserts the CPU micro-sleep lands on one
// event in ThrottleEvery.
//
// The sleep is how a userspace process gives CPU back, so it has to happen;
// what it must not do is happen on every event. Gate() runs on the same
// goroutine that drives the collectors, so a 2ms sleep per event would cap the
// whole agent at 500 events/second and stall telemetry collection along with
// detection.
func TestGovernorThrottleIsAmortised(t *testing.T) {
	t.Parallel()
	cfg := DefaultGovernorConfig()
	cfg.MaxCPUPercent = 5
	cfg.BurstCPUPercent = 15
	cfg.ThrottleEvery = 50
	g := testGovernor(t, cfg)

	// 10% sustained: over the ceiling, under the burst limit.
	g.cpuPercent.Store(int64(10 * 100))

	const n = 500
	start := time.Now()
	for i := 0; i < n; i++ {
		if !g.Gate() {
			t.Fatal("throttling must slow events down, not shed them: shedding is for queue and memory pressure")
		}
	}
	elapsed := time.Since(start)

	st := g.Stats()
	wantThrottles := uint64(n / int(cfg.ThrottleEvery))
	if st.ThrottleCount != wantThrottles {
		t.Errorf("ThrottleCount = %d over %d events at ThrottleEvery=%d, want %d", st.ThrottleCount, n, cfg.ThrottleEvery, wantThrottles)
	}

	// 10 sleeps of 2ms is 20ms. A per-event sleep would have been 1s, so
	// the bound is loose on purpose: it fails the regression, not the CI
	// machine.
	if elapsed > 300*time.Millisecond {
		t.Errorf("500 gated events took %v with the throttle amortised over %d; a per-event sleep is back", elapsed, cfg.ThrottleEvery)
	}
}

// TestGovernorNilIsPermissive asserts a nil governor admits everything.
//
// Callers hold it as an optional field. "Resource governance is not
// configured" must never silently mean "monitoring is off", which is what a
// nil-panic-avoiding `if g != nil` at each call site eventually turns into when
// somebody inverts the condition.
func TestGovernorNilIsPermissive(t *testing.T) {
	t.Parallel()
	var g *ResourceGovernor
	if !g.Gate() {
		t.Error("a nil governor shed an event")
	}
	g.SetQueueDepth(1 << 20)
	g.Start()
	g.Stop()
	if st := g.Stats(); st.EventsAdmitted != 0 || st.Shedding {
		t.Errorf("nil governor Stats() = %+v, want the zero value", st)
	}
}

// TestGovernorStopIsIdempotent asserts a second Stop does not panic on a
// closed channel. Engine.Stop can be called more than once by design.
func TestGovernorStopIsIdempotent(t *testing.T) {
	t.Parallel()
	g := testGovernor(t, DefaultGovernorConfig())
	g.Start()
	g.Stop()
	g.Stop()
}

// TestEngineGateShedsBeforeAnyLayerRuns asserts the wiring: an event the
// governor rejects produces no alerts, is counted as dropped, and is not
// counted as processed.
func TestEngineGateShedsBeforeAnyLayerRuns(t *testing.T) {
	e, err := NewEngine(EngineConfig{WorkerCount: 1}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.governor == nil {
		t.Fatal("NewEngine built an engine with no governor; performance.max_cpu_percent would have no consumer again")
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = e.Stop() }()

	// Force the memory budget shut so every event is over budget, and
	// disable the sample so none get through.
	e.governor.cfg.ShedSampleEvery = 1 << 62
	e.governor.memBytes.Store(e.governor.cfg.MaxMemoryBytes + 1)

	before := e.Stats()
	if alerts := e.Evaluate(context.Background(), struct{}{}); len(alerts) != 0 {
		t.Errorf("a shed event produced %d alerts", len(alerts))
	}
	after := e.Stats()

	if after.DroppedEvents != before.DroppedEvents+1 {
		t.Errorf("DroppedEvents %d -> %d, want +1", before.DroppedEvents, after.DroppedEvents)
	}
	if after.EventsProcessed != before.EventsProcessed {
		t.Errorf("EventsProcessed %d -> %d; a shed event was never processed and must not be counted as if it were",
			before.EventsProcessed, after.EventsProcessed)
	}
	if after.Governor.EventsShed == 0 {
		t.Error("Stats().Governor.EventsShed is 0; the health surface cannot show what the budget cost")
	}
}

// TestEngineGovernorBudgetComesFromConfig asserts the config keys reach the
// governor rather than being dropped on the way.
func TestEngineGovernorBudgetComesFromConfig(t *testing.T) {
	e, err := NewEngine(EngineConfig{WorkerCount: 2, MaxCPUPercent: 2, MaxMemoryMB: 64}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	g := e.Governor()
	if g == nil {
		t.Fatal("Governor() returned nil")
	}
	if g.cfg.MaxCPUPercent != 2 {
		t.Errorf("MaxCPUPercent = %v, want 2 from EngineConfig (performance.max_cpu_percent)", g.cfg.MaxCPUPercent)
	}
	if g.cfg.BurstCPUPercent != 6 {
		t.Errorf("BurstCPUPercent = %v, want 3x the ceiling; a lowered ceiling with a default burst is a ceiling that does nothing", g.cfg.BurstCPUPercent)
	}
	if g.cfg.MaxMemoryBytes != 64*1024*1024 {
		t.Errorf("MaxMemoryBytes = %d, want 64MiB from EngineConfig", g.cfg.MaxMemoryBytes)
	}
	// Watermarks must be reachable: a high watermark above the channel's
	// capacity means shedding can never start.
	if g.cfg.QueueHighWatermark >= cap(e.alertCh) {
		t.Errorf("QueueHighWatermark %d >= alert channel capacity %d, so queue shedding can never trigger",
			g.cfg.QueueHighWatermark, cap(e.alertCh))
	}
	if g.cfg.QueueLowWatermark >= g.cfg.QueueHighWatermark {
		t.Errorf("low watermark %d is not below high watermark %d, so there is no hysteresis band",
			g.cfg.QueueLowWatermark, g.cfg.QueueHighWatermark)
	}
}

// BenchmarkGovernorGateAdmit measures the per-event cost of the gate on the
// path every event now takes.
//
// The number that matters is allocations: Gate() is called once per kernel
// event, and an allocation there is an allocation at the agent's full event
// rate. Run with -benchmem; the assertion is in the companion test below so a
// regression fails the suite rather than only showing up in a benchmark
// nobody reruns.
func BenchmarkGovernorGateAdmit(b *testing.B) {
	g := NewResourceGovernor(DefaultGovernorConfig(), zap.NewNop())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !g.Gate() {
			b.Fatal("shed under no pressure")
		}
	}
}

// BenchmarkGovernorGateShed measures the shed path, which runs when the agent
// is already under pressure and can least afford the gate to be expensive.
func BenchmarkGovernorGateShed(b *testing.B) {
	cfg := DefaultGovernorConfig()
	cfg.QueueHighWatermark = 1
	g := NewResourceGovernor(cfg, zap.NewNop())
	g.SetQueueDepth(1 << 20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Gate()
	}
}

// TestGovernorGateDoesNotAllocate is the benchmark's assertion, so the
// allocation-free property is enforced by `go test` and not by whoever
// remembers to read -benchmem output.
func TestGovernorGateDoesNotAllocate(t *testing.T) {
	g := testGovernor(t, DefaultGovernorConfig())
	// One pass first: the logger and config are touched lazily by the
	// shed path, and AllocsPerRun would attribute first-call costs to
	// every call.
	g.Gate()

	if n := testing.AllocsPerRun(200, func() { g.Gate() }); n != 0 {
		t.Errorf("Gate() allocates %.1f objects per call on the admit path; it runs once per event, so this is one allocation per kernel event", n)
	}

	cfg := DefaultGovernorConfig()
	cfg.QueueHighWatermark = 1
	shed := testGovernor(t, cfg)
	shed.SetQueueDepth(1 << 20)
	shed.Gate()
	if n := testing.AllocsPerRun(200, func() { shed.Gate() }); n != 0 {
		t.Errorf("Gate() allocates %.1f objects per call on the shed path, which runs when the agent is already over budget", n)
	}
}
