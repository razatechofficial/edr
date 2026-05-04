//go:build !linux && !windows && (!(darwin && cgo) || nosec)

package collector

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestNewKernelCollectorOtherIsNonNilWithCapabilityProbe(t *testing.T) {
	kc := NewKernelCollector("ep", config.Config{}, nil)
	if kc == nil {
		t.Fatal("NewKernelCollector returned nil")
	}
	m := kc.ExportMonitoringHealth()
	if m == nil {
		t.Fatal("nil health")
	}
	if m["name"] != "kernel" {
		t.Fatalf("name=%v", m["name"])
	}
	if m["source"] != "capability_probe" {
		t.Fatalf("source=%v", m["source"])
	}
	if m["status"] != "absent" {
		t.Fatalf("status=%v", m["status"])
	}
	if m["reason"] != "tier_minimal_noop" {
		t.Fatalf("reason=%v", m["reason"])
	}
}
