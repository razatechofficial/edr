//go:build linux || windows || (darwin && cgo && !nosec)

package collector

import (
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/kernel"
)

// kernelRingPriority ties userland sampling to ring-buffer producer drops: when
// the kernel→userspace ring reports new drops, we increment the priority
// sampler so lower-priority telemetry can be shed under sustained pressure.
type kernelRingPriority struct {
	s               *PrioritySampler
	lastRingDropped uint64
}

func newKernelRingPriority(cfg config.Config) *kernelRingPriority {
	if !cfg.Monitoring.PrioritySamplingKernel {
		return nil
	}
	th := cfg.Monitoring.PrioritySamplingThreshold
	if th == 0 {
		th = 100
	}
	return &kernelRingPriority{s: NewPrioritySampler(th)}
}

func (k *kernelRingPriority) observeRing(rb *kernel.RingBuffer) {
	if k == nil || k.s == nil || rb == nil {
		return
	}
	d := rb.Stats().Dropped
	if d <= k.lastRingDropped {
		return
	}
	for i := uint64(0); i < d-k.lastRingDropped; i++ {
		k.s.ObserveDrop()
	}
	k.lastRingDropped = d
}

func (k *kernelRingPriority) allowSample(t *Telemetry) bool {
	if k == nil || k.s == nil || t == nil {
		return true
	}
	return k.s.Allow(ClassifyTelemetryPriority(*t))
}
