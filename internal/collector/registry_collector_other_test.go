//go:build !windows && !linux && !darwin

package collector

import "testing"

func TestRareRegistryCollector_HealthSourceAndStatus(t *testing.T) {
	rc := NewRegistryCollector("ep")
	if rc == nil {
		t.Fatal("nil collector")
	}
	h := rc.ExportMonitoringHealth()
	if h == nil {
		t.Fatal("nil health")
	}
	if h["source"] != "rare_registry_probe" {
		t.Fatalf("source=%v", h["source"])
	}
	if h["status"] != "healthy" {
		t.Fatalf("status=%v", h["status"])
	}
}
