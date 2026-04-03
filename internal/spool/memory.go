package spool

import "sync"

type Queue[T any] struct {
	mu    sync.Mutex
	items []T
}

func NewQueue[T any]() *Queue[T] {
	return &Queue[T]{items: make([]T, 0, 256)}
}

func (q *Queue[T]) Push(v T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, v)
}

func (q *Queue[T]) Drain(max int) []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	if max <= 0 || max > len(q.items) {
		max = len(q.items)
	}
	out := append([]T(nil), q.items[:max]...)
	q.items = q.items[max:]
	return out
}
