package telemetry

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// BatcherConfig controls the batching behaviour.
type BatcherConfig struct {
	MaxBatchSize  int
	FlushInterval time.Duration
}

// DefaultBatcherConfig returns production defaults (50 events, 15s flush).
func DefaultBatcherConfig() BatcherConfig {
	return BatcherConfig{
		MaxBatchSize:  50,
		FlushInterval: 15 * time.Second,
	}
}

// FlushFunc is called when a batch is ready to be shipped.
type FlushFunc func(batch []*NormalizedEvent)

// Batcher accumulates NormalizedEvents and flushes them on a timer or when the
// batch reaches capacity. Critical events bypass the batch and invoke the
// flush callback immediately.
type Batcher struct {
	cfg      BatcherConfig
	flushFn  FlushFunc
	logger   *zap.Logger

	mu    sync.Mutex
	batch []*NormalizedEvent

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewBatcher creates a Batcher and starts its background flush goroutine.
// flushFn is invoked each time a batch is ready; it must not block for long.
func NewBatcher(cfg BatcherConfig, flushFn FlushFunc, logger *zap.Logger) *Batcher {
	b := &Batcher{
		cfg:     cfg,
		flushFn: flushFn,
		logger:  logger,
		batch:   make([]*NormalizedEvent, 0, cfg.MaxBatchSize),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	go b.runFlusher()
	return b
}

// Add appends an event to the current batch. Critical events are flushed
// out-of-band immediately without waiting for the batch cycle.
func (b *Batcher) Add(event *NormalizedEvent) {
	if event.Critical {
		b.flushFn([]*NormalizedEvent{event})
		return
	}

	b.mu.Lock()
	b.batch = append(b.batch, event)
	full := len(b.batch) >= b.cfg.MaxBatchSize
	b.mu.Unlock()

	if full {
		b.flushLocked()
	}
}

// Flush returns the current batch and resets the internal buffer. It is safe
// to call concurrently; the caller receives ownership of the returned slice.
func (b *Batcher) Flush() []*NormalizedEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.batch) == 0 {
		return nil
	}
	out := b.batch
	b.batch = make([]*NormalizedEvent, 0, b.cfg.MaxBatchSize)
	return out
}

// Stop terminates the background flusher and performs a final flush.
func (b *Batcher) Stop() {
	b.stopOnce.Do(func() {
		close(b.stopCh)
		<-b.doneCh
		if remaining := b.Flush(); len(remaining) > 0 {
			b.flushFn(remaining)
		}
	})
}

func (b *Batcher) runFlusher() {
	defer close(b.doneCh)
	ticker := time.NewTicker(b.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.flushLocked()
		}
	}
}

func (b *Batcher) flushLocked() {
	batch := b.Flush()
	if len(batch) == 0 {
		return
	}
	b.flushFn(batch)
}
