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
	}
}

// ResourceGovernor monitors agent resource usage and applies backpressure
// when the detection engine exceeds configured budgets.
type ResourceGovernor struct {
	cfg    GovernorConfig
	logger *zap.Logger

	cpuPercent  atomic.Int64
	memBytes    atomic.Uint64
	queueDepth  atomic.Int64
	shedding    atomic.Bool

	stopCh chan struct{}
	wg     sync.WaitGroup

	// Stats
	eventsAdmitted atomic.Uint64
	eventsShed     atomic.Uint64
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
	return &ResourceGovernor{
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start begins background resource monitoring.
func (g *ResourceGovernor) Start() {
	g.wg.Add(1)
	go g.monitorLoop()
}

// Stop halts background monitoring.
func (g *ResourceGovernor) Stop() {
	close(g.stopCh)
	g.wg.Wait()
}

// Gate returns true if the event should be processed, false if it should
// be shed due to resource pressure. It also applies micro-throttling when
// CPU usage is above the sustained limit.
func (g *ResourceGovernor) Gate() bool {
	// Memory budget check
	if g.memBytes.Load() > g.cfg.MaxMemoryBytes {
		g.eventsShed.Add(1)
		return false
	}

	// Queue backpressure
	depth := g.queueDepth.Load()
	if depth > int64(g.cfg.QueueHighWatermark) {
		if !g.shedding.Load() {
			g.shedding.Store(true)
			g.logger.Warn("governor: queue high watermark reached, shedding events",
				zap.Int64("depth", depth))
		}
		g.eventsShed.Add(1)
		return false
	}
	if g.shedding.Load() && depth < int64(g.cfg.QueueLowWatermark) {
		g.shedding.Store(false)
		g.logger.Info("governor: queue below low watermark, resuming")
	}

	// CPU throttle: micro-sleep if sustained usage is above limit
	cpuPct := float64(g.cpuPercent.Load()) / 100.0
	if cpuPct > g.cfg.BurstCPUPercent/100.0 {
		g.throttleCount.Add(1)
		time.Sleep(10 * time.Millisecond)
	} else if cpuPct > g.cfg.MaxCPUPercent/100.0 {
		g.throttleCount.Add(1)
		time.Sleep(2 * time.Millisecond)
	}

	g.eventsAdmitted.Add(1)
	return true
}

// SetQueueDepth updates the governor's view of the current event queue depth.
func (g *ResourceGovernor) SetQueueDepth(depth int) {
	g.queueDepth.Store(int64(depth))
}

// Stats returns resource governor counters.
func (g *ResourceGovernor) Stats() GovernorStats {
	return GovernorStats{
		CPUPercent:     float64(g.cpuPercent.Load()) / 100.0,
		MemoryBytes:    g.memBytes.Load(),
		QueueDepth:     g.queueDepth.Load(),
		EventsAdmitted: g.eventsAdmitted.Load(),
		EventsShed:     g.eventsShed.Load(),
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
	ThrottleCount  uint64
	Shedding       bool
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
