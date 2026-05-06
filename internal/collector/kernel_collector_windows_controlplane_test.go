//go:build windows

package collector

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestControlPlaneReady_BothRequiredHealthy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.WindowsWFPCtlProbe = true
	cfg.Monitoring.WindowsMinifilterPort = `\EdrPort`
	kc := &KernelCollector{cfg: cfg}

	extras := map[string]any{
		"wfp_ctl":        map[string]any{"engine_open": true},
		"minifilter_ctl": map[string]any{"connected": true},
	}
	if !kc.controlPlaneReady(extras) {
		t.Fatal("expected control plane to be ready")
	}
}

func TestControlPlaneReady_RequiredDegraded(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.WindowsWFPCtlProbe = true
	cfg.Monitoring.WindowsMinifilterPort = `\EdrPort`
	kc := &KernelCollector{cfg: cfg}

	extras := map[string]any{
		"wfp_ctl":        map[string]any{"engine_open": false},
		"minifilter_ctl": map[string]any{"connected": true},
	}
	if kc.controlPlaneReady(extras) {
		t.Fatal("expected control plane to be degraded")
	}
}
