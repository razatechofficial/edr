package spool

import "testing"

func TestQueuePushDrain(t *testing.T) {
	q := NewQueue[int]()
	q.Push(1)
	q.Push(2)
	out := q.Drain(1)
	if len(out) != 1 || out[0] != 1 {
		t.Fatalf("unexpected first drain: %#v", out)
	}
	out = q.Drain(10)
	if len(out) != 1 || out[0] != 2 {
		t.Fatalf("unexpected second drain: %#v", out)
	}
}
