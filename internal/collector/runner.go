package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ErrRunnerStopped is returned by Group.Go after Stop has begun.
var ErrRunnerStopped = errors.New("runner: group already stopping")

// Group is the only sanctioned primitive for starting goroutines in the
// monitoring layer. Every goroutine carries a stable name so leaks are
// diagnosable via Group.Stats() and the doctor command. Cancellation is
// propagated through the embedded context; Stop blocks until all goroutines
// have returned or the configured timeout elapses.
type Group struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex // guards: live, stopped
	live     map[string]int
	stopped  bool
	leakHook func(remaining map[string]int)

	started atomic.Uint64
	exited  atomic.Uint64
	panicks atomic.Uint64
}

// NewGroup returns a Group bound to parent. Pass context.Background() if there
// is no upstream context to inherit from.
func NewGroup(parent context.Context) *Group {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &Group{
		ctx:    ctx,
		cancel: cancel,
		live:   make(map[string]int),
	}
}

// Context exposes the group's cancel-aware context for use by workers that
// need to subscribe to shutdown.
func (g *Group) Context() context.Context { return g.ctx }

// SetLeakHook registers a callback fired by Stop when goroutines remain after
// the timeout. Tests use this to fail loudly.
func (g *Group) SetLeakHook(fn func(remaining map[string]int)) {
	g.mu.Lock()
	g.leakHook = fn
	g.mu.Unlock()
}

// Go starts fn in a goroutine identified by name. The function MUST honor
// ctx.Done(); leaving ctx unobserved is a bug. Panics in fn are recovered and
// counted but do not propagate.
func (g *Group) Go(name string, fn func(ctx context.Context)) error {
	if name == "" {
		return errors.New("runner: goroutine name is required")
	}
	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return ErrRunnerStopped
	}
	g.live[name]++
	g.mu.Unlock()

	g.wg.Add(1)
	g.started.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				g.panicks.Add(1)
			}
			g.mu.Lock()
			g.live[name]--
			if g.live[name] <= 0 {
				delete(g.live, name)
			}
			g.mu.Unlock()
			g.exited.Add(1)
		}()
		fn(g.ctx)
	}()
	return nil
}

// Stop cancels the group context and waits up to timeout for all goroutines to
// exit. Returns the names (and counts) of any survivors.
func (g *Group) Stop(timeout time.Duration) map[string]int {
	g.mu.Lock()
	g.stopped = true
	hook := g.leakHook
	g.mu.Unlock()

	g.cancel()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		survivors := g.snapshotLive()
		if hook != nil && len(survivors) > 0 {
			hook(survivors)
		}
		return survivors
	}
}

// Stats returns aggregate counters and a snapshot of live goroutine names.
func (g *Group) Stats() (started, exited, panics uint64, live map[string]int) {
	return g.started.Load(), g.exited.Load(), g.panicks.Load(), g.snapshotLive()
}

func (g *Group) snapshotLive() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	cp := make(map[string]int, len(g.live))
	for k, v := range g.live {
		cp[k] = v
	}
	return cp
}

// MustGo wraps Go and panics on registration failure; intended for static
// startup paths where a missing name is a programming error.
func (g *Group) MustGo(name string, fn func(ctx context.Context)) {
	if err := g.Go(name, fn); err != nil {
		panic(fmt.Sprintf("runner: %s: %v", name, err))
	}
}
