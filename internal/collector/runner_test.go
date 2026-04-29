package collector

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroup_StartsAndExits(t *testing.T) {
	g := NewGroup(context.Background())
	var ran atomic.Bool
	if err := g.Go("worker-a", func(ctx context.Context) {
		<-ctx.Done()
		ran.Store(true)
	}); err != nil {
		t.Fatalf("Go: %v", err)
	}
	if survivors := g.Stop(2 * time.Second); len(survivors) != 0 {
		t.Fatalf("expected clean stop, survivors=%v", survivors)
	}
	if !ran.Load() {
		t.Fatal("worker did not observe cancellation")
	}
	started, exited, panics, _ := g.Stats()
	if started != 1 || exited != 1 || panics != 0 {
		t.Fatalf("stats started=%d exited=%d panics=%d", started, exited, panics)
	}
}

func TestGroup_DetectsLeaksViaHook(t *testing.T) {
	g := NewGroup(context.Background())
	leakedDone := make(chan struct{})
	t.Cleanup(func() { close(leakedDone) })

	var hookFired atomic.Bool
	g.SetLeakHook(func(remaining map[string]int) {
		if remaining["leaker"] != 1 {
			t.Errorf("expected leaker survivor, got %v", remaining)
		}
		hookFired.Store(true)
	})

	_ = g.Go("leaker", func(ctx context.Context) {
		<-leakedDone
	})

	survivors := g.Stop(50 * time.Millisecond)
	if survivors["leaker"] != 1 {
		t.Fatalf("survivors=%v", survivors)
	}
	if !hookFired.Load() {
		t.Fatal("leak hook did not fire")
	}
}

func TestGroup_RecoversFromPanic(t *testing.T) {
	g := NewGroup(context.Background())
	_ = g.Go("panicker", func(ctx context.Context) {
		panic("boom")
	})
	g.Stop(2 * time.Second)
	_, _, panics, _ := g.Stats()
	if panics != 1 {
		t.Fatalf("panics=%d, want 1", panics)
	}
}

func TestGroup_RejectsAfterStop(t *testing.T) {
	g := NewGroup(context.Background())
	g.Stop(50 * time.Millisecond)
	if err := g.Go("late", func(ctx context.Context) {}); err != ErrRunnerStopped {
		t.Fatalf("err=%v, want ErrRunnerStopped", err)
	}
}

func TestGroup_RejectsEmptyName(t *testing.T) {
	g := NewGroup(context.Background())
	defer g.Stop(time.Second)
	if err := g.Go("", func(ctx context.Context) {}); err == nil {
		t.Fatal("expected error for empty name")
	}
}

// TestGroup_NoGoroutineLeak asserts that a clean Stop returns runtime.NumGoroutine to baseline.
func TestGroup_NoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()
	g := NewGroup(context.Background())
	for i := 0; i < 16; i++ {
		_ = g.Go("transient", func(ctx context.Context) {
			<-ctx.Done()
		})
	}
	if survivors := g.Stop(2 * time.Second); len(survivors) != 0 {
		t.Fatalf("survivors=%v", survivors)
	}
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: baseline=%d, current=%d", baseline, runtime.NumGoroutine())
}
