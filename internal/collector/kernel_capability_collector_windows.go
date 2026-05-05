//go:build windows

package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/config"
)

// kernelCapabilityProbeCollector attaches when kernel tier is wanted but
// NewKernelCollector returned nil (not elevated or ETW driver init failure).
type kernelCapabilityProbeCollector struct{}

func newKernelCapabilityProbeCollectorWhenNil(string, config.Config, *UsernameCache) Collector {
	return &kernelCapabilityProbeCollector{}
}

func (k *kernelCapabilityProbeCollector) Name() string { return "kernel" }

func (k *kernelCapabilityProbeCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

func (k *kernelCapabilityProbeCollector) Start(context.Context) error { return nil }

func (k *kernelCapabilityProbeCollector) Stop() {}

func (k *kernelCapabilityProbeCollector) ExportMonitoringHealth() map[string]any {
	cap := kernelCapabilityProbeWindows()
	reason := "etw_driver_init_failed"
	if !cap.RunningAsRoot {
		reason = "not_elevated"
	}
	m := kernelTierCapabilityHealth("capability_probe", cap, reason)
	m["status"] = "degraded"
	m["last_error"] = reason
	return m
}
