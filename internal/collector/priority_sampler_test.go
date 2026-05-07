package collector

import (
	"math/rand"
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestPrioritySampler_bias(t *testing.T) {
	priorityRand = rand.New(rand.NewSource(42))
	ps := NewPrioritySampler(1)
	ps.ObserveDrop()
	n := 0
	for i := 0; i < 200; i++ {
		if ps.Allow(PriorityObserver) {
			n++
		}
	}
	if n > 150 {
		t.Fatalf("expected many observer drops, kept %d/200", n)
	}
	if !ps.Allow(PriorityAuthExec) {
		t.Fatal("auth/exec should not drop")
	}
}

func TestClassifyTelemetryPriority(t *testing.T) {
	if ClassifyTelemetryPriority(Telemetry{Network: &schema.NetworkEvent{}}) != PriorityNetFile {
		t.Fatal("network class")
	}
}
