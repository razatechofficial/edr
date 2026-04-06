package selfprotect

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

const defaultAntiDebugInterval = 5 * time.Second

// AntiDebugger periodically polls for attached debuggers and enters a
// degraded operating mode when one is detected. It never crashes the
// process — detection triggers an alert and reduces functionality.
type AntiDebugger struct {
	logger   *zap.Logger
	interval time.Duration
	mu       sync.RWMutex
	degraded bool
}

// NewAntiDebugger creates an AntiDebugger that polls every 5 seconds.
func NewAntiDebugger(logger *zap.Logger) *AntiDebugger {
	return &AntiDebugger{
		logger:   logger,
		interval: defaultAntiDebugInterval,
	}
}

// Start applies process protection and then polls for debugger attachment
// until ctx is cancelled. It does NOT crash the process on detection;
// instead it enters degraded mode and logs a critical alert.
func (ad *AntiDebugger) Start(ctx context.Context) error {
	if err := ProtectProcess(); err != nil {
		ad.logger.Warn("process protection unavailable", zap.Error(err))
	} else {
		ad.logger.Info("process protection applied")
	}

	ad.logger.Info("anti-debugger monitor started", zap.Duration("interval", ad.interval))
	ticker := time.NewTicker(ad.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if DetectDebugger() {
				ad.mu.Lock()
				if !ad.degraded {
					ad.logger.Error("debugger detected — entering degraded mode")
				}
				ad.degraded = true
				ad.mu.Unlock()
			}
		}
	}
}

// IsDegraded reports whether the agent is operating in degraded mode
// because a debugger was detected.
func (ad *AntiDebugger) IsDegraded() bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.degraded
}
