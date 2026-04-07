package baseline

import (
	"testing"

	"go.uber.org/zap"
)

func TestBaselineEngineAnomaly(t *testing.T) {
	t.Parallel()
	e := NewBaselineEngine(0, zap.NewNop())
	for i := 0; i < 20; i++ {
		e.AddObservation("proc.cpu", "bash", 10)
	}
	anomaly, _ := e.IsAnomaly("proc.cpu", "bash", 95)
	if !anomaly {
		t.Fatalf("expected anomaly for high outlier")
	}
}
