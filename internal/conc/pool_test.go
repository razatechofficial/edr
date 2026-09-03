package conc

import "testing"

func TestPoolRunsAndDrops(t *testing.T) {
	p := NewPool(2, 2)
	defer p.Close()
	done := make(chan struct{}, 8)
	ok := 0
	for i := 0; i < 8; i++ {
		if p.Submit(func() { done <- struct{}{} }) {
			ok++
		}
	}
	if ok < 2 {
		t.Fatalf("expected some jobs accepted, got %d", ok)
	}
	got := 0
	for i := 0; i < ok; i++ {
		<-done
		got++
	}
	if got != ok {
		t.Fatalf("ran %d want %d", got, ok)
	}
	p.Close()
	if p.Submit(func() {}) {
		t.Fatal("submit after close should fail")
	}
}
