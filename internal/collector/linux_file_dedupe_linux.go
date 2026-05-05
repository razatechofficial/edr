//go:build linux

package collector

import (
	"sync"
	"sync/atomic"
	"time"
)

// LinuxFileDeduper suppresses duplicate file paths across Linux streaming sources
// (fanotify vs audit) within a short time window.
type LinuxFileDeduper struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time
	skip   atomic.Uint64
}

// NewLinuxFileDeduper returns nil when window <= 0.
func NewLinuxFileDeduper(window time.Duration) *LinuxFileDeduper {
	if window <= 0 {
		return nil
	}
	return &LinuxFileDeduper{
		window: window,
		last:   make(map[string]time.Time),
	}
}

// Allow reports whether this path should produce telemetry (false = suppressed as duplicate).
func (d *LinuxFileDeduper) Allow(path string) bool {
	if d == nil || path == "" {
		return true
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[path]; ok && now.Sub(t) < d.window {
		d.skip.Add(1)
		return false
	}
	d.last[path] = now
	if len(d.last) > 10000 {
		cutoff := now.Add(-2 * d.window)
		for k, ts := range d.last {
			if ts.Before(cutoff) {
				delete(d.last, k)
			}
		}
	}
	return true
}

// Skipped returns how many emissions were deduplicated.
func (d *LinuxFileDeduper) Skipped() uint64 {
	if d == nil {
		return 0
	}
	return d.skip.Load()
}
