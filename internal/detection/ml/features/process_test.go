package features

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestBehavioralFeatureExtractorExtract(t *testing.T) {
	t.Parallel()

	ex := NewBehavioralFeatureExtractor(4)
	window := []interface{}{
		schema.ProcessEvent{
			ProcessName: "bash",
			User:        "root",
			PID:         100,
			PPID:        1,
			BaseEvent: schema.BaseEvent{
				Timestamp: time.Now().UTC(),
			},
		},
		schema.FileEvent{
			Operation: "write",
			BaseEvent: schema.BaseEvent{
				Timestamp: time.Now().UTC(),
			},
		},
		schema.NetworkEvent{
			Protocol:  "tcp",
			BaseEvent: schema.BaseEvent{
				Timestamp: time.Now().UTC(),
			},
		},
	}

	feats := ex.Extract(window)
	if len(feats) != ex.WindowSize()*FeaturesPerEvent {
		t.Fatalf("unexpected feature count: got=%d want=%d", len(feats), ex.WindowSize()*FeaturesPerEvent)
	}
	if feats[0] != 1.0 {
		t.Fatalf("expected first event to encode process_create")
	}
}
