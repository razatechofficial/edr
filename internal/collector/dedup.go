package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

const defaultFileDedupeWindow = 500 * time.Millisecond

// FileDeduper suppresses duplicate file telemetry within a time window.
// Keys are SHA-256 hex of "event_type|pid|path|operation" (stable, bounded length).
type FileDeduper struct {
	mu     sync.Mutex
	last   map[string]time.Time
	window time.Duration
}

// NewFileDeduper returns a deduper with the given suppression window (default 500ms).
func NewFileDeduper(window time.Duration) *FileDeduper {
	if window <= 0 {
		window = defaultFileDedupeWindow
	}
	return &FileDeduper{
		last:   make(map[string]time.Time),
		window: window,
	}
}

func fileDedupeKey(eventType schema.EventType, pid int, path, operation string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s", eventType, pid, path, operation)))
	return hex.EncodeToString(h[:])
}

// ShouldEmitFile returns false if the same file event key was seen within the window.
// Apply only to file telemetry (caller must restrict to FileEvent path).
func (d *FileDeduper) ShouldEmitFile(eventType schema.EventType, pid int, path, operation string) bool {
	if path == "" {
		return true
	}
	op := operation
	if op == "" {
		op = "event"
	}
	key := fileDedupeKey(eventType, pid, path, op)
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[key]; ok && now.Sub(t) < d.window {
		return false
	}
	d.last[key] = now
	return true
}
