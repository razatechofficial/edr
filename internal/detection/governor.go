package detection

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// GovernorConfig controls resource usage limits for the detection engine.
type GovernorConfig struct {
	// MaxCPUPercent is the sustained CPU usage ceiling (0-100). Default: 5%.
	MaxCPUPercent float64
	// BurstCPUPercent is the transient burst ceiling (0-100). Default: 15%.
	BurstCPUPercent float64
	// MaxMemoryBytes is the RSS ceiling. Default: 256MB.
	MaxMemoryBytes uint64
	// QueueHighWatermark triggers event shedding. Default: 10000.
	QueueHighWatermark int
	// QueueLowWatermark resumes normal processing. Default: 5000.
	QueueLowWatermark int
	// SampleInterval controls how often resource usage is polled. Default: 1s.
	SampleInterval time.Duration

	// ShedSampleEvery keeps one event in N while shedding, instead of
	// dropping all of them. Default: 16. Set to 1 to keep everything (which
	// defeats shedding) or to 0 for the default.
	//
	// Dropping every event under pressure makes the agent blind at exactly
	// the moment something is generating enough activity to cause the
	// pressure, which is the moment an EDR is least useful blind. A
	// deterministic one-in-N sample costs a bounded fraction of the work and
	// keeps the detection layers seeing the shape of what is happening; the
	// shed counter says how much was not seen, so nobody mistakes the
	// sample for the whole.
	ShedSampleEvery uint64

	// ThrottleEvery applies the CPU micro-sleep on one admitted event in N
	// rather than on every one. Default: 64.
	//
	// The sleep is how the governor gives CPU back: there is no other way
	// for a userspace process to cap its own usage. But sleeping 2ms on
	// every event caps throughput at 500 events/second the instant CPU goes
	// over budget, and Gate() runs on the same goroutine that drives the
	// collectors, so that stall is paid by telemetry collection as well as
	// by detection. Amortising it over N events keeps the same duty cycle
	// available while bounding the per-event latency cost to 1/N of it.
	ThrottleEvery uint64
}

// DefaultGovernorConfig returns conservative resource limits matching
// industry-standard EDR agents (CrowdStrike, SentinelOne).
func DefaultGovernorConfig() GovernorConfig {
	return GovernorConfig{
		MaxCPUPercent:      5.0,
		BurstCPUPercent:    15.0,
		MaxMemoryBytes:     256 * 1024 * 1024,
		QueueHighWatermark: 10000,
		QueueLowWatermark:  5000,
		SampleInterval:     time.Second,
		ShedSampleEvery:    16,
		ThrottleEvery:      64,
	}
}

// ResourceGovernor monitors agent resource usage and applies backpressure
// when the detection engine exceeds configured budgets.
type ResourceGovernor struct {
	cfg    GovernorConfig
	logger *zap.Logger

	cpuPercent atomic.Int64
	memBytes   atomic.Uint64
	queueDepth atomic.Int64
	shedding   atomic.Bool

	// shedSeq and throttleSeq count calls so the shed sample and the CPU
	// micro-sleep can be applied to one call in N without a timer or a
	// random source. Both are plain atomic adds: Gate() is on the hot path
	// of every event and must not allocate.
	shedSeq     atomic.Uint64
	throttleSeq atomic.Uint64

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Stats
	eventsAdmitted atomic.Uint64
	eventsShed     atomic.Uint64
	eventsSampled  atomic.Uint64
	throttleCount  atomic.Uint64
}

// NewResourceGovernor creates a governor that enforces resource budgets.
func NewResourceGovernor(cfg GovernorConfig, logger *zap.Logger) *ResourceGovernor {
	if cfg.MaxCPUPercent <= 0 {
		cfg.MaxCPUPercent = 5.0
	}
	if cfg.BurstCPUPercent <= 0 {
		cfg.BurstCPUPercent = 15.0
	}
	if cfg.MaxMemoryBytes == 0 {
		cfg.MaxMemoryBytes = 256 * 1024 * 1024
	}
	if cfg.QueueHighWatermark <= 0 {
		cfg.QueueHighWatermark = 10000
	}
	if cfg.QueueLowWatermark <= 0 {
		cfg.QueueLowWatermark = 5000
	}
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = time.Second
	}
	if cfg.ShedSampleEvery == 0 {
		cfg.ShedSampleEvery = 16
	}
	if cfg.ThrottleEvery == 0 {
		cfg.ThrottleEvery = 64
	}
	return &ResourceGovernor{
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start begins background resource monitoring.
func (g *ResourceGovernor) Start() {
	if g == nil {
		return
	}
	g.wg.Add(1)
	go g.monitorLoop()
}

// Stop halts background monitoring.
func (g *ResourceGovernor) Stop() {
	if g == nil {
		return
	}
	g.stopOnce.Do(func() {
		close(g.stopCh)
		g.wg.Wait()
	})
}

// Gate returns true if the event should be processed, false if it should
// be shed due to resource pressure. It also applies micro-throttling when
// CPU usage is above the sustained limit.
func (g *ResourceGovernor) Gate() bool {
	if g == nil {
		// A nil governor admits everything. Callers hold one as an
		// optional field, and "governance not configured" must not mean
		// "monitoring off".
		return true
	}

	// Memory budget check.
	if g.memBytes.Load() > g.cfg.MaxMemoryBytes {
		return g.shed()
	}

	// Queue backpressure.
	depth := g.queueDepth.Load()
	if depth > int64(g.cfg.QueueHighWatermark) {
		if g.shedding.CompareAndSwap(false, true) {
			g.logger.Warn("governor: queue high watermark reached, shedding events",
				zap.Int64("depth", depth),
				zap.Int("high_watermark", g.cfg.QueueHighWatermark),
				zap.Uint64("keeping_one_in", g.cfg.ShedSampleEvery))
		}
		return g.shed()
	}
	if depth < int64(g.cfg.QueueLowWatermark) && g.shedding.CompareAndSwap(true, false) {
		g.logger.Info("governor: queue below low watermark, resuming",
			zap.Int64("depth", depth))
	}

	g.throttleCPU()
	g.eventsAdmitted.Add(1)
	return true
}

// shed decides whether this over-budget event is the one in N that is kept.
//
// Counting rather than sampling randomly keeps the decision deterministic,
// allocation-free and reproducible in a test, and over any window it admits
// the same fraction a random sample would.
func (g *ResourceGovernor) shed() bool {
	if g.cfg.ShedSampleEvery <= 1 {
		g.eventsAdmitted.Add(1)
		return true
	}
	if g.shedSeq.Add(1)%g.cfg.ShedSampleEvery != 0 {
		g.eventsShed.Add(1)
		return false
	}
	g.eventsSampled.Add(1)
	g.eventsAdmitted.Add(1)
	return true
}

// throttleCPU yields the processor when sustained usage is over budget.
//
// The sleep lands on one admitted event in ThrottleEvery, so the duty cycle is
// the same as a per-event sleep of 1/N the duration without making any single
// event pay the whole of it.
func (g *ResourceGovernor) throttleCPU() {
	cpuPct := float64(g.cpuPercent.Load()) / 100.0
	var nap time.Duration
	switch {
	case cpuPct > g.cfg.BurstCPUPercent/100.0:
		nap = 10 * time.Millisecond
	case cpuPct > g.cfg.MaxCPUPercent/100.0:
		nap = 2 * time.Millisecond
	default:
		return
	}
	if g.cfg.ThrottleEvery > 1 && g.throttleSeq.Add(1)%g.cfg.ThrottleEvery != 0 {
		return
	}
	g.throttleCount.Add(1)
	time.Sleep(nap)
}

// SetQueueDepth updates the governor's view of the current event queue depth.
func (g *ResourceGovernor) SetQueueDepth(depth int) {
	if g == nil {
		return
	}
	g.queueDepth.Store(int64(depth))
}

// Stats returns resource governor counters.
func (g *ResourceGovernor) Stats() GovernorStats {
	if g == nil {
		return GovernorStats{}
	}
	return GovernorStats{
		CPUPercent:     float64(g.cpuPercent.Load()) / 100.0,
		MemoryBytes:    g.memBytes.Load(),
		QueueDepth:     g.queueDepth.Load(),
		EventsAdmitted: g.eventsAdmitted.Load(),
		EventsShed:     g.eventsShed.Load(),
		EventsSampled:  g.eventsSampled.Load(),
		ThrottleCount:  g.throttleCount.Load(),
		Shedding:       g.shedding.Load(),
	}
}

// GovernorStats exposes runtime resource metrics.
type GovernorStats struct {
	CPUPercent     float64
	MemoryBytes    uint64
	QueueDepth     int64
	EventsAdmitted uint64
	EventsShed     uint64
	// EventsSampled counts events admitted *while shedding*, i.e. the one
	// in ShedSampleEvery that was kept. EventsAdmitted includes them.
	EventsSampled uint64
	ThrottleCount uint64
	Shedding      bool
}

func (g *ResourceGovernor) monitorLoop() {
	defer g.wg.Done()
	ticker := time.NewTicker(g.cfg.SampleInterval)
	defer ticker.Stop()

	var lastCPU time.Duration
	var lastSample time.Time

	for {
		select {
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.sampleMemory()
			lastCPU, lastSample = g.sampleCPU(lastCPU, lastSample)
		}
	}
}

func (g *ResourceGovernor) sampleMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	g.memBytes.Store(m.Sys)
}

func (g *ResourceGovernor) sampleCPU(lastCPU time.Duration, lastSample time.Time) (time.Duration, time.Time) {
	now := time.Now()
	currentCPU := cpuTime()

	if !lastSample.IsZero() {
		elapsed := now.Sub(lastSample)
		if elapsed > 0 {
			used := currentCPU - lastCPU
			pct := float64(used) / float64(elapsed) * 100.0
			g.cpuPercent.Store(int64(pct * 100)) // stored as pct * 100 for precision
		}
	}

	return currentCPU, now
}
