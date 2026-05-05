//go:build darwin

package kernel

import (
	"context"
	"sync"
	"time"
)

// ESFRevocationProbe schedules periodic lightweight checks for entitlement /
// FDA posture drift. Full TCC revocation detection requires Apple-private APIs;
// this probe records heartbeat evidence for monitoring_health.json.
type ESFRevocationProbe struct {
	mu sync.RWMutex

	lastTick    time.Time
	lastOutcome string
}

// NewESFRevocationProbe constructs a revocation heartbeat probe.
func NewESFRevocationProbe() *ESFRevocationProbe {
	return &ESFRevocationProbe{lastOutcome: "initialized"}
}

// Run executes the periodic probe until ctx is cancelled.
func (p *ESFRevocationProbe) Run(ctx context.Context) {
	if p == nil {
		return
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	p.record("ok", "scheduled_probe")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Placeholder: ES clients typically fail closed on restart when entitlements
			// are revoked; runtime detection without ES SPI remains best-effort.
			p.record("ok", "heartbeat")
		}
	}
}

func (p *ESFRevocationProbe) record(outcome, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastTick = time.Now()
	p.lastOutcome = outcome + ":" + detail
}

// Health exports probe heartbeat for monitoring_health.json.
func (p *ESFRevocationProbe) Health() map[string]any {
	if p == nil {
		return map[string]any{"esf_revocation_probe": "nil"}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return map[string]any{
		"esf_revocation_last_tick_unix": p.lastTick.Unix(),
		"esf_revocation_outcome":        p.lastOutcome,
	}
}
