// Package conc provides bounded worker pools so the agent never fans out
// one goroutine per event/command (Go production practice: workers ≈ cores,
// backpressure via a fixed queue; drop rather than grow memory).
package conc

import (
	"sync"
	"sync/atomic"
)

// Pool is a fixed set of goroutines pulling work from a buffered channel.
// Close waits for in-flight jobs; Submit after Close is a no-op.
type Pool struct {
	jobs    chan func()
	stopCh  chan struct{}
	wg      sync.WaitGroup
	closed  atomic.Bool
	drops   atomic.Uint64
}

// NewPool starts workers long-lived goroutines. queue is the backpressure
// buffer; Submit drops when the buffer is full (never blocks the caller).
func NewPool(workers, queue int) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queue < 1 {
		queue = 32
	}
	p := &Pool{
		jobs:   make(chan func(), queue),
		stopCh: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.loop()
	}
	return p
}

func (p *Pool) loop() {
	defer p.wg.Done()
	for {
		select {
		case fn := <-p.jobs:
			if fn != nil {
				fn()
			}
		case <-p.stopCh:
			return
		}
	}
}

// Submit queues fn. Returns false if the pool is closed or the queue is full.
func (p *Pool) Submit(fn func()) bool {
	if fn == nil || p.closed.Load() {
		return false
	}
	select {
	case p.jobs <- fn:
		return true
	default:
		p.drops.Add(1)
		return false
	}
}

// Dropped is the number of jobs rejected because the queue was full.
func (p *Pool) Dropped() uint64 { return p.drops.Load() }

// Close stops workers after draining queued jobs. Safe to call once.
func (p *Pool) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	close(p.stopCh)
	p.wg.Wait()
}
