//go:build !linux && !windows && (!(darwin && cgo) || nosec)

package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/config"
)

// NewKernelCollector returns a non-nil tier-minimal kernel capability probe so
// monitoring_health always carries an explicit kernel row on rare GOOS builds.
func NewKernelCollector(_ string, _ config.Config, _ *UsernameCache) *KernelCollector {
	return &KernelCollector{probe: kernelCapabilityProbe()}
}

// KernelCollector is a capability probe on non-Linux/non-Windows builds (and
// macOS CGO-less / nosec builds). It satisfies Collector and StartableCollector.
type KernelCollector struct {
	probe kernelCapability
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Collect(_ context.Context) ([]Telemetry, error) { return nil, nil }

func (kc *KernelCollector) Start(_ context.Context) error { return nil }

func (kc *KernelCollector) Stop() {}

// ExportMonitoringHealth surfaces explicit absent kernel telemetry with probe facts.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil {
		return nil
	}
	return kernelTierCapabilityHealth("capability_probe", kc.probe, "tier_minimal_noop")
}
