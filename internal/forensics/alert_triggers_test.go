package forensics

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestCollectArtifactsForAlertBounded(t *testing.T) {
	ctx := context.Background()
	bundle, err := CollectArtifactsForAlert(ctx, zap.NewNop(), AlertTriggerMeta{AlertID: "a1", RuleID: "r1", Severity: "high"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil {
		t.Fatal("nil bundle")
	}
	if bundle.Hostname == "" {
		t.Error("want hostname populated")
	}
}
