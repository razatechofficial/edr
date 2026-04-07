package features

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestNetworkFeatureExtractorExtract(t *testing.T) {
	t.Parallel()

	ex := &NetworkFeatureExtractor{}
	feats := ex.Extract(schema.NetworkEvent{
		SourcePt: 53000,
		DestPt:   443,
		Protocol: "tcp",
		Domain:   "example.com",
		DestIP:   "8.8.8.8",
		BaseEvent: schema.BaseEvent{
			Timestamp: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		},
	})

	if len(feats) != ex.FeatureCount() {
		t.Fatalf("unexpected feature count: got=%d want=%d", len(feats), ex.FeatureCount())
	}
	if feats[5] != 1.0 {
		t.Fatalf("expected https port feature flag")
	}
	if feats[8] != 1.0 {
		t.Fatalf("expected tcp feature flag")
	}
	if feats[12] != 1.0 {
		t.Fatalf("expected domain-present feature flag")
	}
}
