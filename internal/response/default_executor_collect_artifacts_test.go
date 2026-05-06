package response

import (
	"context"
	"testing"

	"github.com/razatechofficial/edr/internal/detection"
	"go.uber.org/zap"
)

func TestDefaultExecutorCollectArtifacts(t *testing.T) {
	t.Parallel()
	e := &DefaultActionExecutor{
		Logger:   zap.NewNop(),
		HostID:   "endpoint-1",
		Eng:      newTestEngine(t),
	}
	d := detection.Detection{
		ID:     "alert-synth",
		RuleID: "rule-test",
		Severity: detection.P2,
	}
	if err := e.Execute(context.Background(), "collect_artifacts", nil, d); err != nil {
		t.Fatal(err)
	}
}
