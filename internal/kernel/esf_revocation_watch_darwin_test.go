//go:build darwin

package kernel

import (
	"context"
	"testing"
	"time"
)

func TestESFRevocationProbeRecordFailure(t *testing.T) {
	p := NewESFRevocationProbe()
	p.RecordFailure("probe_failed")
	h := p.Health()
	if st, _ := h["esf_revocation_status"].(string); st != "degraded" {
		t.Fatalf("status=%v want degraded", h["esf_revocation_status"])
	}
}

func TestESFRevocationProbeStaleHeartbeatDegrades(t *testing.T) {
	p := NewESFRevocationProbe()
	p.interval = 10 * time.Millisecond
	p.mu.Lock()
	p.lastTick = time.Now().Add(-100 * time.Millisecond)
	p.lastOutcome = "ok:heartbeat"
	p.mu.Unlock()
	h := p.Health()
	if st, _ := h["esf_revocation_status"].(string); st != "degraded" {
		t.Fatalf("status=%v want degraded for stale heartbeat", h["esf_revocation_status"])
	}
}

func TestESFRevocationProbeInjectedCmdOutcomes(t *testing.T) {
	p := NewESFRevocationProbe()
	p.ProbeCmd = func(ctx context.Context, name string) ([]byte, error) {
		switch name {
		case "probe_sip":
			return []byte("System Integrity Protection status: enabled."), nil
		case "probe_tccutil":
			return []byte("usage"), nil
		case "probe_sysext":
			return []byte("line1\nline2\n"), nil
		default:
			return nil, context.Canceled
		}
	}
	p.runConcreteProbes(context.Background())
	h := p.Health()
	probes, _ := h["esf_revocation_probes"].(map[string]string)
	if probes == nil {
		t.Fatalf("missing esf_revocation_probes: %#v", h)
	}
	if probes["probe_sip"] == "" || probes["probe_sysext"] == "" {
		t.Fatalf("unexpected probes: %#v", probes)
	}
	if st, _ := h["esf_revocation_status"].(string); st != "healthy" {
		t.Fatalf("status=%v want healthy", h["esf_revocation_status"])
	}
}

