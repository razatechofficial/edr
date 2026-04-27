package spool

import "sync"

type Queue[T any] struct {
	mu       sync.Mutex
	items    []T
	maxItems int
}

func NewQueue[T any]() *Queue[T] {
	return NewQueueWithLimit[T](4096)
}

func NewQueueWithLimit[T any](maxItems int) *Queue[T] {
	if maxItems <= 0 {
		maxItems = 4096
	}
	return &Queue[T]{items: make([]T, 0, 256), maxItems: maxItems}
}

func (q *Queue[T]) Push(v T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		// Keep bounded memory usage by evicting oldest entries.
		copy(q.items, q.items[1:])
		var zero T
		q.items[len(q.items)-1] = zero
		q.items = q.items[:len(q.items)-1]
	}
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
