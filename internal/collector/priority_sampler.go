package collector

import (
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// PriorityClass is a coarse event priority for probabilistic drops under pressure.
type PriorityClass int

const (
	PriorityAuthExec PriorityClass = 1
	PriorityNetFile  PriorityClass = 2
	PriorityObserver PriorityClass = 3
)

// priorityRand is process-local; tests may seed for determinism.
var priorityRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// ClassifyTelemetryPriority maps telemetry to a priority band for sampling.
func ClassifyTelemetryPriority(t Telemetry) PriorityClass {
	switch {
	case t.Auth != nil, t.Process != nil && t.Process.EventType == schema.EventProcess:
		return PriorityAuthExec
	case t.Network != nil, t.File != nil:
		return PriorityNetFile
	default:
		return PriorityObserver
	}
}

// PrioritySampler applies class-biased random drops when recentDrops exceeds threshold.
type PrioritySampler struct {
	recentDrops atomic.Uint64
	threshold   uint64
}

// NewPrioritySampler returns a sampler that drops class-3 first when drops > threshold.
func NewPrioritySampler(threshold uint64) *PrioritySampler {
	if threshold == 0 {
		threshold = 100
	}
	return &PrioritySampler{threshold: threshold}
}

func (p *PrioritySampler) ObserveDrop() {
	p.recentDrops.Add(1)
}

// Allow returns false when the event should be dropped under simulated pressure.
func (p *PrioritySampler) Allow(class PriorityClass) bool {
	if p.recentDrops.Load() < p.threshold {
		return true
	}
	switch class {
	case PriorityAuthExec:
		return true
	case PriorityNetFile:
		return priorityRand.Float64() > 0.05
	default:
		return priorityRand.Float64() > 0.35
	}
}
