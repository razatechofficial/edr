package collector

import (
	"encoding/binary"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

const (
	defaultFileDedupeWindow = 500 * time.Millisecond
	defaultDedupCap         = 8192
)

// EventDeduper is a generic, bounded suppressor used by every monitoring
// collector. Keys are arbitrary strings (collector-specific); the time-of-last
// emit is stored in a BoundedLRU so memory growth is capped regardless of
// cardinality. This replaces the unbounded ad-hoc maps that used to live in
// FileDeduper.last, NetworkCollector.seen, and DNSCollector.seen.
type EventDeduper struct {
	cache *BoundedLRU[string, time.Time]
}

// NewEventDeduper builds a deduper. cap <= 0 defaults to defaultDedupCap; ttl
// <= 0 disables TTL eviction (the LRU still bounds memory).
func NewEventDeduper(cap int, ttl time.Duration) *EventDeduper {
	if cap <= 0 {
		cap = defaultDedupCap
	}
	return &EventDeduper{cache: NewBoundedLRU[string, time.Time](cap, ttl)}
}

// ShouldEmit returns true if the key has not been seen within the window. On
// emit it stamps the current time so future calls within the window suppress.
func (d *EventDeduper) ShouldEmit(key string, window time.Duration) bool {
	if d == nil || key == "" {
		return true
	}
	now := time.Now()
	if last, ok := d.cache.Get(key); ok && window > 0 && now.Sub(last) < window {
		return false
	}
	d.cache.Put(key, now)
	return true
}

// Sweep evicts TTL-expired entries; safe to call from a janitor goroutine.
func (d *EventDeduper) Sweep() int {
	if d == nil {
		return 0
	}
	return d.cache.Sweep()
}

// Stats returns size, evictions, and TTL-expirations.
func (d *EventDeduper) Stats() (size int, evictions, expirations uint64) {
	if d == nil {
		return 0, 0, 0
	}
	return d.cache.Stats()
}

// FileDeduper preserves the original file-event suppression API on top of the
// generic EventDeduper. The window argument from NewFileDeduper is honored as
// before; cardinality is now bounded.
type FileDeduper struct {
	inner  *EventDeduper
	window time.Duration
}

// NewFileDeduper returns a deduper with the given suppression window (default 500ms).
func NewFileDeduper(window time.Duration) *FileDeduper {
	if window <= 0 {
		window = defaultFileDedupeWindow
	}
	// TTL is set to 4x the window: enough to cover bursts, small enough to
	// prevent cold keys from pinning memory.
	return &FileDeduper{
		inner:  NewEventDeduper(defaultDedupCap, 4*window),
		window: window,
	}
}

// fileDedupeKey hashes the dedupe inputs to a fixed-width string using
// FNV-64a. P1-19: SHA-256 was overkill for a non-cryptographic dedupe
// table and showed up as a measurable CPU cost in profiles when file
// event rates spiked. FNV-64a is ~30x faster, allocation-free, and
// 64 bits of state is more than sufficient at the cache capacities we
// run (8192-entry LRU, collision probability negligible).
//
// We render the digest as a 16-char hex string so the existing
// BoundedLRU[string, ...] keeps working without an API change; if the
// LRU ever moves to a uint64-keyed map (planned for P2) drop the
// strconv.FormatUint here and return the raw uint64 instead.
func fileDedupeKey(eventType schema.EventType, pid int, path, operation string) string {
	h := fnv.New64a()
	h.Write([]byte(eventType))
	h.Write([]byte{'|'})
	var pidBuf [8]byte
	binary.LittleEndian.PutUint64(pidBuf[:], uint64(pid))
	h.Write(pidBuf[:])
	h.Write([]byte{'|'})
	h.Write([]byte(path))
	h.Write([]byte{'|'})
	h.Write([]byte(operation))
	return strconv.FormatUint(h.Sum64(), 16)
}

// ShouldEmitFile returns false if the same file event key was seen within the
// window. Apply only to file telemetry (caller must restrict to FileEvent path).
func (d *FileDeduper) ShouldEmitFile(eventType schema.EventType, pid int, path, operation string) bool {
	if path == "" {
		return true
	}
	op := operation
	if op == "" {
		op = "event"
	}
	key := fileDedupeKey(eventType, pid, path, op)
	return d.inner.ShouldEmit(key, d.window)
}

// Sweep evicts TTL-expired entries.
func (d *FileDeduper) Sweep() int {
	if d == nil {
		return 0
	}
	return d.inner.Sweep()
}

// Stats returns size, evictions, and TTL-expirations.
func (d *FileDeduper) Stats() (size int, evictions, expirations uint64) {
	if d == nil {
		return 0, 0, 0
	}
	return d.inner.Stats()
}
