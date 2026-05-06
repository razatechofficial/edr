package collector

import (
	"sync"
	"sync/atomic"
	"time"
)

// Source priority for Linux file dedupe: higher wins on duplicate path within window.
const (
	DedupeSourceFanotify = 1
	DedupeSourceAudit    = 4
	DedupeSourceEBPF     = 6
)

// LinuxFileDeduper suppresses duplicate file paths across Linux streaming sources
// (fanotify vs audit) within a short time window.
type LinuxFileDeduper struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]pathDedupeEntry
	skip   atomic.Uint64
}

type pathDedupeEntry struct {
	at    time.Time
	score int
}

// NewLinuxFileDeduper returns nil when window <= 0.
func NewLinuxFileDeduper(window time.Duration) *LinuxFileDeduper {
	if window <= 0 {
		return nil
	}
	return &LinuxFileDeduper{
		window: window,
		last:   make(map[string]pathDedupeEntry),
	}
}

// Allow reports whether this path should produce telemetry (false = suppressed as duplicate).
func (d *LinuxFileDeduper) Allow(path string) bool {
	return d.AllowWithSource(path, DedupeSourceFanotify)
}

// AllowWithSource applies time-window dedupe; a higher source score replaces a lower one.
func (d *LinuxFileDeduper) AllowWithSource(path string, sourceScore int) bool {
	if d == nil || path == "" {
		return true
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if prev, ok := d.last[path]; ok && now.Sub(prev.at) < d.window {
		if sourceScore > prev.score {
			d.last[path] = pathDedupeEntry{at: now, score: sourceScore}
			return true
		}
		d.skip.Add(1)
		return false
	}
	d.last[path] = pathDedupeEntry{at: now, score: sourceScore}
	if len(d.last) > 10000 {
		cutoff := now.Add(-2 * d.window)
		for k, ent := range d.last {
			if ent.at.Before(cutoff) {
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

// StatsMap returns deduplication counters for monitoring health exports.
func (d *LinuxFileDeduper) StatsMap() map[string]any {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	n := len(d.last)
	d.mu.Unlock()
	return map[string]any{
		"skipped_total": d.skip.Load(),
		"tracked_paths": n,
	}
}
