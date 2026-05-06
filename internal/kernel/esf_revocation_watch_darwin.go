//go:build darwin

package kernel

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ESFRevocationProbe schedules periodic checks for SIP / sysext / tccutil posture (best-effort).
type ESFRevocationProbe struct {
	mu sync.RWMutex

	lastTick    time.Time
	lastOutcome string
	interval    time.Duration
	degradedCnt uint64

	lastProbeResults map[string]string
	sysextBundleID   string

	// ProbeCmd, when set, runs named probes (probe_sip, probe_tccutil, probe_sysext) instead of exec.
	ProbeCmd func(ctx context.Context, probeName string) ([]byte, error)
}

// NewESFRevocationProbe constructs a revocation heartbeat probe.
func NewESFRevocationProbe() *ESFRevocationProbe {
	return &ESFRevocationProbe{
		lastOutcome: "initialized",
		interval:    5 * time.Minute,
	}
}

// SetSysextBundleID configures an optional bundle id substring for sysext list parsing.
func (p *ESFRevocationProbe) SetSysextBundleID(id string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.sysextBundleID = strings.TrimSpace(id)
	p.mu.Unlock()
}

// Run executes the periodic probe until ctx is cancelled.
func (p *ESFRevocationProbe) Run(ctx context.Context) {
	if p == nil {
		return
	}
	interval := 5 * time.Minute
	if p.interval > 0 {
		interval = p.interval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	p.record("ok", "scheduled_probe")
	p.runConcreteProbes(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.runConcreteProbes(ctx)
		}
	}
}

func (p *ESFRevocationProbe) runProbeOutput(ctx context.Context, probeName, path string, args ...string) ([]byte, error) {
	if p.ProbeCmd != nil {
		return p.ProbeCmd(ctx, probeName)
	}
	return exec.CommandContext(ctx, path, args...).CombinedOutput()
}

func (p *ESFRevocationProbe) runConcreteProbes(ctx context.Context) {
	if p == nil {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	results := map[string]string{}

	out, err := p.runProbeOutput(probeCtx, "probe_sip", "/usr/sbin/csrutil", "status")
	if err != nil {
		results["probe_sip"] = "error:" + err.Error()
	} else {
		results["probe_sip"] = strings.TrimSpace(string(out))
	}

	out2, err2 := p.runProbeOutput(probeCtx, "probe_tccutil", "/usr/bin/tccutil")
	if err2 != nil {
		results["probe_tccutil"] = "unreachable:" + err2.Error()
	} else if len(bytes.TrimSpace(out2)) > 0 {
		results["probe_tccutil"] = "ok"
	} else {
		results["probe_tccutil"] = "empty_output"
	}

	out3, err3 := p.runProbeOutput(probeCtx, "probe_sysext", "/usr/sbin/systemextensionsctl", "list")
	if err3 != nil {
		results["probe_sysext"] = "error:" + err3.Error()
	} else {
		lines := bytes.Count(out3, []byte{'\n'})
		results["probe_sysext"] = "lines:" + strconv.Itoa(lines)
		p.mu.RLock()
		bid := p.sysextBundleID
		p.mu.RUnlock()
		if bid != "" {
			if strings.Contains(strings.ToLower(string(out3)), strings.ToLower(bid)) {
				results["probe_sysext_bundle"] = "matched"
			} else {
				results["probe_sysext_bundle"] = "missing:" + bid
			}
		}
	}

	outcome := "ok"
	detail := "probes_complete"
	for k, v := range results {
		if strings.HasPrefix(v, "error:") || strings.HasPrefix(v, "unreachable:") {
			outcome = "degraded"
			detail = k + ":" + v
			break
		}
	}
	if b, ok := results["probe_sysext_bundle"]; ok && strings.HasPrefix(b, "missing:") {
		outcome = "degraded"
		detail = b
	}

	p.mu.Lock()
	p.lastProbeResults = results
	p.mu.Unlock()
	p.record(outcome, detail)
}

func (p *ESFRevocationProbe) record(outcome, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastTick = time.Now()
	p.lastOutcome = outcome + ":" + detail
	if outcome == "degraded" {
		p.degradedCnt++
	}
}

// RecordFailure marks explicit entitlement/FDA/extension-related degradation.
func (p *ESFRevocationProbe) RecordFailure(detail string) {
	if p == nil {
		return
	}
	p.record("degraded", detail)
}

// Health exports probe heartbeat for monitoring_health.json.
func (p *ESFRevocationProbe) Health() map[string]any {
	if p == nil {
		return map[string]any{"esf_revocation_probe": "nil"}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	status := "healthy"
	if time.Since(p.lastTick) > 2*p.interval && !p.lastTick.IsZero() {
		status = "degraded"
	}
	if len(p.lastOutcome) >= 8 && p.lastOutcome[:8] == "degraded" {
		status = "degraded"
	}
	out := map[string]any{
		"esf_revocation_last_tick_unix": p.lastTick.Unix(),
		"esf_revocation_outcome":        p.lastOutcome,
		"esf_revocation_status":         status,
		"esf_revocation_degraded_cnt":   p.degradedCnt,
	}
	if len(p.lastProbeResults) > 0 {
		out["esf_revocation_probes"] = p.lastProbeResults
	}
	return out
}
