//go:build !linux

package collector

import "context"

// NewKernelCollector returns nil on non-Linux platforms.
// eBPF kernel telemetry is only available on Linux.
func NewKernelCollector(_ string) *KernelCollector {
	return nil
}

// KernelCollector is a placeholder on non-Linux platforms. It satisfies the
// Collector and StartableCollector interfaces so DefaultCollectors compiles
// cross-platform, but NewKernelCollector always returns nil.
type KernelCollector struct{}

func (kc *KernelCollector) Name() string                                  { return "kernel" }
func (kc *KernelCollector) Collect(_ context.Context) ([]Telemetry, error) { return nil, nil }
func (kc *KernelCollector) Start(_ context.Context) error                 { return nil }
func (kc *KernelCollector) Stop()                                         {}
