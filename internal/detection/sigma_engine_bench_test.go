package detection

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/events"
)

func BenchmarkDetectionEngine_Process(b *testing.B) {
	e := &Engine{
		logger:  zap.NewNop(),
		running: true,
		alertCh: make(chan *events.Alert, 1024),
		scorer:  NewScoringEngine(),
		deduper: NewAlertDeduper(5),
	}
	event := map[string]interface{}{
		"event_type":  "process",
		"pid":         1234,
		"endpoint_id": "bench",
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = e.Process(context.Background(), event)
		}
	})
}
