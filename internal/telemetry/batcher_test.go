package telemetry

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestBatcherSizeFlush(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var flushed []*NormalizedEvent

	cfg := BatcherConfig{
		MaxBatchSize:  5,
		FlushInterval: 10 * time.Second,
	}
	b := NewBatcher(cfg, func(batch []*NormalizedEvent) {
		mu.Lock()
		flushed = append(flushed, batch...)
		mu.Unlock()
	}, zap.NewNop())
	defer b.Stop()

	for i := range cfg.MaxBatchSize {
		b.Add(&NormalizedEvent{EventType: "process", PID: i + 1})
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	n := len(flushed)
	mu.Unlock()

	if n != cfg.MaxBatchSize {
		t.Errorf("flushed %d events, want %d", n, cfg.MaxBatchSize)
	}
}

func TestBatcherTimeFlush(t *testing.T) {
	t.Parallel()

	var flushedCount atomic.Int32

	cfg := BatcherConfig{
		MaxBatchSize:  100,
		FlushInterval: 100 * time.Millisecond,
	}
	b := NewBatcher(cfg, func(batch []*NormalizedEvent) {
		flushedCount.Add(int32(len(batch)))
	}, zap.NewNop())
	defer b.Stop()

	b.Add(&NormalizedEvent{EventType: "file"})
	b.Add(&NormalizedEvent{EventType: "file"})

	time.Sleep(300 * time.Millisecond)

	if n := flushedCount.Load(); n != 2 {
		t.Errorf("flushed %d events after time interval, want 2", n)
	}
}

func TestBatcherCriticalBypass(t *testing.T) {
	t.Parallel()

	var criticalReceived atomic.Bool

	cfg := BatcherConfig{
		MaxBatchSize:  100,
		FlushInterval: 10 * time.Second,
	}
	b := NewBatcher(cfg, func(batch []*NormalizedEvent) {
		for _, e := range batch {
			if e.Critical {
				criticalReceived.Store(true)
			}
		}
	}, zap.NewNop())
	defer b.Stop()

	b.Add(&NormalizedEvent{
		EventType: "alert",
		Critical:  true,
		Severity:  "critical",
	})

	time.Sleep(20 * time.Millisecond)

	if !criticalReceived.Load() {
		t.Error("critical event was not flushed immediately")
	}

	pending := b.Flush()
	for _, e := range pending {
		if e.Critical {
			t.Error("critical event should not be in pending batch")
		}
	}
}

func TestBatcherStop(t *testing.T) {
	t.Parallel()

	var flushedCount atomic.Int32

	cfg := BatcherConfig{
		MaxBatchSize:  100,
		FlushInterval: 10 * time.Second,
	}
	b := NewBatcher(cfg, func(batch []*NormalizedEvent) {
		flushedCount.Add(int32(len(batch)))
	}, zap.NewNop())

	b.Add(&NormalizedEvent{EventType: "process"})
	b.Add(&NormalizedEvent{EventType: "file"})
	b.Add(&NormalizedEvent{EventType: "network"})

	b.Stop()

	if n := flushedCount.Load(); n != 3 {
		t.Errorf("Stop should flush remaining %d events, flushed %d", 3, n)
	}
}
