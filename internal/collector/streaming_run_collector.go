package collector

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// StreamingSink is the outbound sink passed to streamingRunCollector run loops.
// Send honors ctx cancellation and performs a non-blocking channel send; drops
// are counted into the owning collector when the buffer is full.
type StreamingSink struct {
	ch        chan<- Telemetry
	drop      *atomic.Uint64
	rateDrops *atomic.Uint64
	rl        *streamEPSLimiter
}

// Send attempts a non-blocking send. Returns true if the telemetry was queued.
func (s *StreamingSink) Send(ctx context.Context, t Telemetry) bool {
	if s == nil || s.ch == nil {
		return false
	}
	if s.rl != nil && !s.rl.allow(time.Now()) {
		if s.rateDrops != nil {
			s.rateDrops.Add(1)
		}
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case s.ch <- t:
		return true
	default:
		if s.drop != nil {
			s.drop.Add(1)
		}
		return false
	}
}

type streamEPSLimiter struct {
	max   int64
	sec   atomic.Int64
	count atomic.Int64
}

func newStreamEPSLimiter(maxEPS int) *streamEPSLimiter {
	if maxEPS <= 0 {
		return nil
	}
	return &streamEPSLimiter{max: int64(maxEPS)}
}

func (l *streamEPSLimiter) allow(now time.Time) bool {
	sec := now.Unix()
	ls := l.sec.Load()
	if ls != sec {
		l.sec.Store(sec)
		l.count.Store(0)
	}
	for {
		c := l.count.Load()
		if c >= l.max {
			return false
		}
		if l.count.CompareAndSwap(c, c+1) {
			return true
		}
	}
}

// streamingRunCollector adapts a blocking Run(ctx, sink) loop into a
// StartableCollector that drains into the agent Collect tick. The outbound
// channel is bounded for backpressure.
type streamingRunCollector struct {
	name   string
	depth  int
	maxEPS int

	run    func(context.Context, *StreamingSink) error
	health func() map[string]any

	dropped       atomic.Uint64
	rateDropCount atomic.Uint64

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
	out    chan Telemetry
}

func newStreamingRunCollector(name string, bufDepth int, maxEPSPerSec int, run func(context.Context, *StreamingSink) error, health func() map[string]any) *streamingRunCollector {
	if bufDepth <= 0 {
		bufDepth = 256
	}
	return &streamingRunCollector{name: name, depth: bufDepth, maxEPS: maxEPSPerSec, run: run, health: health}
}

func (r *streamingRunCollector) Name() string { return r.name }

func (r *streamingRunCollector) Collect(_ context.Context) ([]Telemetry, error) {
	r.mu.Lock()
	ch := r.out
	r.mu.Unlock()
	if ch == nil {
		return nil, nil
	}
	var batch []Telemetry
	for {
		select {
		case t := <-ch:
			batch = append(batch, t)
		default:
			return batch, nil
		}
	}
}

func (r *streamingRunCollector) ExportMonitoringHealth() map[string]any {
	r.mu.Lock()
	ch := r.out
	depth := 0
	if ch != nil {
		depth = len(ch)
	}
	r.mu.Unlock()
	dropped := r.dropped.Load()

	var merged map[string]any
	if r.health != nil {
		if hm := r.health(); hm != nil {
			merged = make(map[string]any, len(hm)+4)
			for k, v := range hm {
				merged[k] = v
			}
		}
	}
	if merged == nil {
		merged = MonitoringSource{
			Name:       r.name,
			OS:         runtime.GOOS,
			Source:     "streaming",
			Status:     "healthy",
			QueueDepth: depth,
			Dropped:    dropped,
		}.ToMap()
		return merged
	}
	merged["queue_depth"] = depth
	merged["dropped"] = dropped
	if rl := r.rateDropCount.Load(); rl > 0 {
		merged["rate_limited_drops"] = rl
	}
	return merged
}

func (r *streamingRunCollector) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		return nil
	}
	ctx2, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.out = make(chan Telemetry, r.depth)
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.wg.Done()
		sink := &StreamingSink{
			ch:        r.out,
			drop:      &r.dropped,
			rateDrops: &r.rateDropCount,
			rl:        newStreamEPSLimiter(r.maxEPS),
		}
		_ = r.run(ctx2, sink)
	}()
	return nil
}

func (r *streamingRunCollector) Stop() {
	r.mu.Lock()
	cc := r.cancel
	r.cancel = nil
	ch := r.out
	r.out = nil
	r.mu.Unlock()
	if cc != nil {
		cc()
	}
	r.wg.Wait()
	if ch != nil {
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}
