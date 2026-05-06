//go:build !linux

package collector

import (
	"context"
	"runtime"
	"strings"
)

func (p *PostureCollector) runOptionalPostureProbes(ctx context.Context) {
	if p == nil || len(p.cfg.Monitoring.PostureProbes) == 0 {
		return
	}
	out := map[string]any{}
	for _, raw := range p.cfg.Monitoring.PostureProbes {
		name := strings.ToLower(strings.TrimSpace(raw))
		if ctx.Err() != nil {
			break
		}
		out[name] = map[string]any{
			"status": "limited",
			"goos":   runtime.GOOS,
			"note":   "full rootcheck-lite pack runs on linux; enable posture_suid_sweep on darwin/windows when expanded",
		}
	}
	p.mu.Lock()
	p.probeOut = out
	p.mu.Unlock()
}
