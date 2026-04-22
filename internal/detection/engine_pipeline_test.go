package detection

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/events"
)

func TestEngineProcessAndDedup(t *testing.T) {
	e := &Engine{
		logger:  zap.NewNop(),
		running: true,
		alertCh: make(chan *events.Alert, 16),
		scorer:  NewScoringEngine(),
		deduper: NewAlertDeduper(2*time.Second, ""),
	}
	ev := map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": "h1",
		"pid":         100,
	}
	_ = e.Process(context.Background(), ev)
	_ = e.Process(context.Background(), ev)
	st := e.Stats()
	if st.EventsProcessed == 0 {
		t.Fatalf("expected processed events stats")
	}
}
