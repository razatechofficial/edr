package collector

import (
	"sync"
	"testing"
	"time"
)

func TestEPSLimiter_AllowsWhenDisabled(t *testing.T) {
	l := NewEPSLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		if !l.Allow() {
			t.Fatal("limiter with rate=0 must allow all")
		}
	}
	allowed, rejected := l.Stats()
	if allowed != 1000 || rejected != 0 {
		t.Fatalf("allowed=%d rejected=%d", allowed, rejected)
	}
}

func TestEPSLimiter_BurstThenRefill(t *testing.T) {
	l := NewEPSLimiter(10, 5)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	l.last = now
	l.tokens = 5
	for i := 0; i < 5; i++ {
		if !l.Allow() {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if l.Allow() {
		t.Fatal("expected denial after burst")
	}
	now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < 20; i++ {
		if l.Allow() {
			allowed++
		}
	}
	if allowed < 5 || allowed > 11 {
		t.Fatalf("after 1s refill, allowed=%d, want ~10", allowed)
	}
}

func TestBoundedRing_FIFO(t *testing.T) {
	r := NewBoundedRing[int](4)
	for i := 1; i <= 4; i++ {
		if !r.TryPush(i) {
			t.Fatalf("push %d failed", i)
		}
	}
	if r.TryPush(5) {
		t.Fatal("expected drop when full")
	}
	got := r.Pop(make([]int, 0, 4), 0)
	want := []int{1, 2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d", len(got), len(want))
	}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("got[%d]=%d, want %d", i, got[i], v)
		}
	}
	pushed, popped, dropped := r.Stats()
	if pushed != 4 || popped != 4 || dropped != 1 {
		t.Fatalf("pushed=%d popped=%d dropped=%d", pushed, popped, dropped)
	}
}

func TestBoundedRing_Concurrent(t *testing.T) {
	r := NewBoundedRing[int](128)
	const total = 1000
	producerDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(producerDone)
		for i := 0; i < total; i++ {
			r.TryPush(i)
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]int, 0, 64)
		for {
			buf = r.Pop(buf[:0], 64)
			if len(buf) == 0 {
				select {
				case <-producerDone:
					if r.Len() == 0 {
						return
					}
				default:
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()
	wg.Wait()
	if r.Len() != 0 {
		t.Fatalf("ring not drained: len=%d", r.Len())
	}
	pushed, popped, dropped := r.Stats()
	if pushed+dropped != total {
		t.Fatalf("pushed+dropped=%d, want %d", pushed+dropped, total)
	}
	if pushed != popped {
		t.Fatalf("pushed=%d popped=%d (must equal)", pushed, popped)
	}
}
