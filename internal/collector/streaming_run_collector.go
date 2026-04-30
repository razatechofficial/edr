package collector

import (
	"context"
	"sync"
)

// streamingRunCollector adapts a blocking Run(ctx, out) loop into a
// StartableCollector that drains into the agent Collect tick. The outbound
// channel is bounded for backpressure; sends use non-blocking select with drop
// semantics inside each source's Run implementation where applicable.
type streamingRunCollector struct {
	name   string
	depth  int
	run    func(context.Context, chan<- Telemetry) error
	health func() map[string]any

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
	out    chan Telemetry
}

func newStreamingRunCollector(name string, bufDepth int, run func(context.Context, chan<- Telemetry) error, health func() map[string]any) *streamingRunCollector {
	if bufDepth <= 0 {
		bufDepth = 256
	}
	return &streamingRunCollector{name: name, depth: bufDepth, run: run, health: health}
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
	if r.health != nil {
		return r.health()
	}
	return nil
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
		_ = r.run(ctx2, r.out)
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
