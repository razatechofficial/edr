package collector

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LineageEntry describes the durable identity of a process for cross-event
// correlation. Fields are populated lazily by collectors when the data becomes
// available; partial entries are valid.
type LineageEntry struct {
	PID              uint32
	ParentPID        uint32
	StartNS          uint64
	UID              uint32
	GID              uint32
	User             string
	ImagePath        string
	ImageHash        string
	Comm             string
	CommandLine      string
	Cgroup           string
	ContainerID      string
	ContainerRuntime string
	LineageID        string // sha1(pid|start_ns) - stable per (pid, start_ns)
	UpdatedAt        time.Time
}

// Clone returns a defensive copy so callers can mutate without racing.
func (e *LineageEntry) Clone() LineageEntry {
	if e == nil {
		return LineageEntry{}
	}
	return *e
}

// LineageTracker is a process-keyed LRU. It is the single source of truth for
// process identity in the monitoring layer; every emitted event must call
// Tracker.Stamp() to attach LineageID + parent + container fields.
type LineageTracker struct {
	cache *BoundedLRU[uint32, *LineageEntry]
	mu    sync.Mutex // guards: hits/misses counters
	hits  uint64
	miss  uint64
}

// NewLineageTracker returns a tracker with cap entries and ttl idle eviction.
// Defaults: cap=65536, ttl=1h.
func NewLineageTracker(cap int, ttl time.Duration) *LineageTracker {
	if cap <= 0 {
		cap = 65536
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &LineageTracker{cache: NewBoundedLRU[uint32, *LineageEntry](cap, ttl)}
}

// Get returns a snapshot of the lineage entry for pid. ok is false on miss.
func (t *LineageTracker) Get(pid uint32) (LineageEntry, bool) {
	v, ok := t.cache.Get(pid)
	t.mu.Lock()
	if ok {
		t.hits++
	} else {
		t.miss++
	}
	t.mu.Unlock()
	if !ok || v == nil {
		return LineageEntry{}, false
	}
	return v.Clone(), true
}

// Upsert merges non-zero fields from delta into the existing entry (or inserts
// a new one). The merged entry's LineageID is recomputed when StartNS changes.
func (t *LineageTracker) Upsert(delta LineageEntry) LineageEntry {
	if delta.PID == 0 {
		return delta
	}
	existing, ok := t.cache.Get(delta.PID)
	merged := &LineageEntry{}
	if ok && existing != nil {
		*merged = *existing
	}
	mergeNonEmpty(merged, &delta)
	merged.PID = delta.PID
	if merged.StartNS == 0 && delta.StartNS != 0 {
		merged.StartNS = delta.StartNS
	}
	merged.LineageID = computeLineageID(merged.PID, merged.StartNS)
	merged.UpdatedAt = time.Now()
	t.cache.Put(delta.PID, merged)
	return merged.Clone()
}

// Forget removes a pid (typically called on process exit).
func (t *LineageTracker) Forget(pid uint32) { t.cache.Delete(pid) }

// Sweep evicts TTL-expired entries; safe to call on a timer.
func (t *LineageTracker) Sweep() int { return t.cache.Sweep() }

// Stats returns size, evictions, and hit/miss counters.
func (t *LineageTracker) Stats() (size int, evictions, expirations, hits, misses uint64) {
	size, evictions, expirations = t.cache.Stats()
	t.mu.Lock()
	hits, misses = t.hits, t.miss
	t.mu.Unlock()
	return
}

// LineageIDFor returns the stable id for (pid, startNs) without touching the
// cache. Used by collectors that already hold a snapshot.
func LineageIDFor(pid uint32, startNS uint64) string { return computeLineageID(pid, startNS) }

func computeLineageID(pid uint32, startNS uint64) string {
	if pid == 0 {
		return ""
	}
	var buf [20]byte
	n := strconv.AppendUint(buf[:0], uint64(pid), 10)
	n = append(n, '|')
	n = strconv.AppendUint(n, startNS, 10)
	sum := sha1.Sum(n)
	return hex.EncodeToString(sum[:8]) // 16 hex chars; collision risk is negligible for endpoint-local use
}

func mergeNonEmpty(dst, src *LineageEntry) {
	if src.ParentPID != 0 {
		dst.ParentPID = src.ParentPID
	}
	if src.UID != 0 {
		dst.UID = src.UID
	}
	if src.GID != 0 {
		dst.GID = src.GID
	}
	if src.User != "" {
		dst.User = src.User
	}
	if src.ImagePath != "" {
		dst.ImagePath = src.ImagePath
	}
	if src.ImageHash != "" {
		dst.ImageHash = src.ImageHash
	}
	if src.Comm != "" {
		dst.Comm = src.Comm
	}
	if src.CommandLine != "" {
		dst.CommandLine = src.CommandLine
	}
	if src.Cgroup != "" {
		dst.Cgroup = src.Cgroup
	}
	if src.ContainerID != "" {
		dst.ContainerID = src.ContainerID
	}
	if src.ContainerRuntime != "" {
		dst.ContainerRuntime = src.ContainerRuntime
	}
}

// ParseContainerFromCgroup recognizes Docker / containerd / cri-o / kubepods
// patterns and returns (containerID, runtime). It is OS-agnostic; Linux
// callers feed the contents of /proc/<pid>/cgroup line by line.
func ParseContainerFromCgroup(cgroupLines string) (id, runtime string) {
	for _, raw := range strings.Split(cgroupLines, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if i := strings.LastIndex(line, "/"); i >= 0 {
			tok := line[i+1:]
			switch {
			case strings.HasPrefix(tok, "docker-"):
				return trimSuffixScope(strings.TrimPrefix(tok, "docker-")), "docker"
			case strings.HasPrefix(tok, "cri-containerd-"):
				return trimSuffixScope(strings.TrimPrefix(tok, "cri-containerd-")), "containerd"
			case strings.HasPrefix(tok, "crio-"):
				return trimSuffixScope(strings.TrimPrefix(tok, "crio-")), "crio"
			case strings.Contains(line, "kubepods"):
				return trimSuffixScope(tok), "kubepods"
			case strings.HasPrefix(tok, "containerd-"):
				return trimSuffixScope(strings.TrimPrefix(tok, "containerd-")), "containerd"
			}
		}
	}
	return "", ""
}

func trimSuffixScope(s string) string {
	if i := strings.Index(s, ".scope"); i > 0 {
		s = s[:i]
	}
	return s
}
