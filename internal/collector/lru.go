// Package collector provides shared monitoring-layer primitives.
//
// BoundedLRU is a generic, size-bounded, optionally TTL-aware cache that all
// monitoring collectors must use instead of ad-hoc maps. It guarantees O(1)
// Get/Put/Delete and prevents the unbounded-map memory leaks that previously
// existed in NetworkCollector.seen, DNSCollector.seen, and FileDeduper.last.
package collector

import (
	"sync"
	"time"
)

// nowFunc is overridden in tests.
type nowFunc func() time.Time

type lruNode[K comparable, V any] struct {
	key   K
	val   V
	at    time.Time
	prev  *lruNode[K, V]
	next  *lruNode[K, V]
}

// BoundedLRU is a thread-safe, fixed-capacity LRU cache.
// Zero value is unusable; use NewBoundedLRU.
type BoundedLRU[K comparable, V any] struct {
	mu       sync.Mutex // guards: items, head, tail, len
	items    map[K]*lruNode[K, V]
	head     *lruNode[K, V] // most-recently-used
	tail     *lruNode[K, V] // least-recently-used
	cap      int
	ttl      time.Duration
	now      nowFunc
	evicts   uint64
	expires  uint64
}

// NewBoundedLRU constructs an LRU with the given capacity and optional TTL.
// A non-positive cap defaults to 4096; a non-positive ttl disables expiry.
func NewBoundedLRU[K comparable, V any](cap int, ttl time.Duration) *BoundedLRU[K, V] {
	if cap <= 0 {
		cap = 4096
	}
	return &BoundedLRU[K, V]{
		items: make(map[K]*lruNode[K, V], cap),
		cap:   cap,
		ttl:   ttl,
		now:   time.Now,
	}
}

// Len returns the current cache size.
func (l *BoundedLRU[K, V]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

// Stats returns lifetime eviction and TTL-expiry counters.
func (l *BoundedLRU[K, V]) Stats() (size int, evictions, expirations uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items), l.evicts, l.expires
}

// Get returns the value for key, refreshing its LRU position. found is false
// when the key is absent or its TTL has elapsed.
func (l *BoundedLRU[K, V]) Get(key K) (V, bool) {
	var zero V
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.items[key]
	if !ok {
		return zero, false
	}
	if l.ttl > 0 && l.now().Sub(n.at) > l.ttl {
		l.removeNodeLocked(n)
		l.expires++
		return zero, false
	}
	l.moveToFrontLocked(n)
	return n.val, true
}

// Put inserts or updates key=>val and bumps it to MRU. If the cache is at
// capacity the LRU entry is evicted.
func (l *BoundedLRU[K, V]) Put(key K, val V) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n, ok := l.items[key]; ok {
		n.val = val
		n.at = l.now()
		l.moveToFrontLocked(n)
		return
	}
	n := &lruNode[K, V]{key: key, val: val, at: l.now()}
	l.items[key] = n
	l.pushFrontLocked(n)
	if len(l.items) > l.cap {
		victim := l.tail
		if victim != nil {
			l.removeNodeLocked(victim)
			l.evicts++
		}
	}
}

// Delete removes a key. Returns true if the key was present.
func (l *BoundedLRU[K, V]) Delete(key K) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.items[key]
	if !ok {
		return false
	}
	l.removeNodeLocked(n)
	return true
}

// Purge drops every entry. Used at shutdown to release references.
func (l *BoundedLRU[K, V]) Purge() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = make(map[K]*lruNode[K, V], l.cap)
	l.head, l.tail = nil, nil
}

// Sweep removes all TTL-expired entries; safe to call from a background goroutine.
// Returns the number of entries reaped.
func (l *BoundedLRU[K, V]) Sweep() int {
	if l.ttl <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.ttl)
	reaped := 0
	for n := l.tail; n != nil; {
		prev := n.prev
		if n.at.After(cutoff) {
			break
		}
		l.removeNodeLocked(n)
		l.expires++
		reaped++
		n = prev
	}
	return reaped
}

func (l *BoundedLRU[K, V]) pushFrontLocked(n *lruNode[K, V]) {
	n.prev = nil
	n.next = l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *BoundedLRU[K, V]) moveToFrontLocked(n *lruNode[K, V]) {
	if n == l.head {
		return
	}
	if n.prev != nil {
		n.prev.next = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	}
	if n == l.tail {
		l.tail = n.prev
	}
	n.prev, n.next = nil, l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
}

func (l *BoundedLRU[K, V]) removeNodeLocked(n *lruNode[K, V]) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		l.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		l.tail = n.prev
	}
	n.prev, n.next = nil, nil
	delete(l.items, n.key)
}
