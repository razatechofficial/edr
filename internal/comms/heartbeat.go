package comms

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// HeartbeatPayload is the periodic health report sent to the control-plane.
type HeartbeatPayload struct {
	AgentID          string    `json:"agent_id"`
	AgentVersion     string    `json:"agent_version"`
	Hostname         string    `json:"hostname"`
	OS               string    `json:"os"`
	Arch             string    `json:"arch"`
	Uptime           float64   `json:"uptime_seconds"`
	CPUPercent       float64   `json:"cpu_percent"`
	MemoryMB         float64   `json:"memory_mb"`
	GoRoutines       int       `json:"goroutines"`
	LastDetectionAt  time.Time `json:"last_detection_at,omitempty"`
	EventsProcessed  uint64    `json:"events_processed"`
	EventsDropped    uint64    `json:"events_dropped"`
	AlertsGenerated  uint64    `json:"alerts_generated"`
	SpoolDepth       int       `json:"spool_depth"`
	Timestamp        time.Time `json:"timestamp"`
}

// HeartbeatTransport sends serialised heartbeat payloads to the server.
type HeartbeatTransport interface {
	SendHeartbeat(ctx context.Context, data []byte) error
}

// Heartbeat manages periodic health reporting to the control-plane server.
type Heartbeat struct {
	agentID      string
	agentVersion string
	hostname     string
	transport    HeartbeatTransport
	logger       *zap.Logger
	startTime    time.Time

	eventsProcessed atomic.Uint64
	eventsDropped   atomic.Uint64
	alertsGenerated atomic.Uint64

	mu              sync.RWMutex
	lastDetectionAt time.Time
	spoolDepth      int
	cpuPercent      float64
	memoryMB        float64

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewHeartbeat creates a Heartbeat reporter.
func NewHeartbeat(agentID, agentVersion, hostname string, transport HeartbeatTransport, logger *zap.Logger) *Heartbeat {
	return &Heartbeat{
		agentID:      agentID,
		agentVersion: agentVersion,
		hostname:     hostname,
		transport:    transport,
		logger:       logger,
		startTime:    time.Now(),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// Start begins sending heartbeats at the given interval. It blocks the
// calling goroutine only for the initial send.
func (h *Heartbeat) Start(ctx context.Context, interval time.Duration) error {
	if err := h.sendOnce(ctx); err != nil {
		h.logger.Warn("initial heartbeat failed", zap.Error(err))
	}
	go h.loop(ctx, interval)
	return nil
}

// Stop terminates the heartbeat loop.
func (h *Heartbeat) Stop() {
	h.stopOnce.Do(func() {
		close(h.stopCh)
		<-h.doneCh
	})
}

// RecordEvent increments the events-processed counter.
func (h *Heartbeat) RecordEvent() { h.eventsProcessed.Add(1) }

// RecordDrop increments the events-dropped counter.
func (h *Heartbeat) RecordDrop() { h.eventsDropped.Add(1) }

// RecordAlert increments the alerts-generated counter and records the time.
func (h *Heartbeat) RecordAlert() {
	h.alertsGenerated.Add(1)
	h.mu.Lock()
	h.lastDetectionAt = time.Now().UTC()
	h.mu.Unlock()
}

// UpdateResourceUsage allows an external monitor to push CPU/memory stats.
func (h *Heartbeat) UpdateResourceUsage(cpuPercent, memoryMB float64) {
	h.mu.Lock()
	h.cpuPercent = cpuPercent
	h.memoryMB = memoryMB
	h.mu.Unlock()
}

// UpdateSpoolDepth sets the current number of spooled events.
func (h *Heartbeat) UpdateSpoolDepth(depth int) {
	h.mu.Lock()
	h.spoolDepth = depth
	h.mu.Unlock()
}

func (h *Heartbeat) buildPayload() HeartbeatPayload {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return HeartbeatPayload{
		AgentID:         h.agentID,
		AgentVersion:    h.agentVersion,
		Hostname:        h.hostname,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Uptime:          time.Since(h.startTime).Seconds(),
		CPUPercent:      h.cpuPercent,
		MemoryMB:        float64(memStats.Alloc) / (1024 * 1024),
		GoRoutines:      runtime.NumGoroutine(),
		LastDetectionAt: h.lastDetectionAt,
		EventsProcessed: h.eventsProcessed.Load(),
		EventsDropped:   h.eventsDropped.Load(),
		AlertsGenerated: h.alertsGenerated.Load(),
		SpoolDepth:      h.spoolDepth,
		Timestamp:       time.Now().UTC(),
	}
}

func (h *Heartbeat) sendOnce(ctx context.Context) error {
	payload := h.buildPayload()
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return h.transport.SendHeartbeat(ctx, data)
}

func (h *Heartbeat) loop(ctx context.Context, interval time.Duration) {
	defer close(h.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.sendOnce(ctx); err != nil {
				h.logger.Warn("heartbeat send failed", zap.Error(err))
			}
		}
	}
}
