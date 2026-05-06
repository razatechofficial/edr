//go:build darwin

package kernel

import (
	"context"
	"errors"
	"testing"
)

func TestNetworkExtensionCtlProbeSuccess(t *testing.T) {
	ctl := NewNetworkExtensionCtl("")
	ctl.probeCmd = func(ctx context.Context) ([]byte, error) {
		return []byte("active enabled extension"), nil
	}
	if err := ctl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if ok := ctl.Probe(context.Background()); !ok {
		t.Fatal("Probe should succeed")
	}
	h := ctl.Health()
	if st, _ := h["network_extension_status"].(string); st != "running_scaffold" {
		t.Fatalf("status=%v want running_scaffold", h["network_extension_status"])
	}
}

func TestNetworkExtensionCtlProbeDegraded(t *testing.T) {
	ctl := NewNetworkExtensionCtl("")
	ctl.probeCmd = func(ctx context.Context) ([]byte, error) {
		return nil, errors.New("systemextensionsctl failed")
	}
	if err := ctl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if ok := ctl.Probe(context.Background()); ok {
		t.Fatal("Probe should fail")
	}
	h := ctl.Health()
	if st, _ := h["network_extension_status"].(string); st != "degraded" {
		t.Fatalf("status=%v want degraded", h["network_extension_status"])
	}
}

