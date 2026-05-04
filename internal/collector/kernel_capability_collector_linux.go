//go:build linux

package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/config"
)

// kernelCapabilityProbeCollector attaches when kernel tier is wanted but
// NewKernelCollector returned nil (non-root or eBPF init failure).
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
	cap := kernelCapabilityProbe()
	reason := "ebpf_init_failed"
	// kernelCapabilityProbe uses unix geteuid; imported via probe_unix.
	if !cap.RunningAsRoot {
		reason = "non_root"
	}
	return kernelTierCapabilityHealth("capability_probe", cap, reason)
}
