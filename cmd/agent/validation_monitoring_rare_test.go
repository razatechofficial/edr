//go:build !linux && !darwin && !windows

package main

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestPerOSExpectedSources_RareIncludesAuthDNSKernelWhenTier(t *testing.T) {
	defs := config.Defaults()
	cfg := &defs
	cfg.Monitoring.KernelEnabled = true
	cfg.Monitoring.Mode = "auto"
	cfg.Monitoring.RequireKernel = false
	got := perOSExpectedSources(cfg)
	if !containsWant(got, "dns") || !containsWant(got, "kernel") || !containsWant(got, "auth") {
		t.Fatalf("expected auth+dns+kernel tier: %v", got)
	}
}
