package telemetryqueue

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const segmentMax = 64 << 20 // rotate segment after 64MiB

// Stats holds queue metrics for health reporting.
type Stats struct {
	QueueDepth int
	BytesUsed  int64
	DropCount  int64
	LastDrain  time.Time
}

// Manager is a capped, append-only multi-segment JSONL queue.
type Manager struct {
	mu           sync.Mutex
	dir          string
	maxTotal     int64
	seq          atomic.Uint64
	currentPath  string
	current      *os.File
	currentSize  int64
	totalBytes   int64
	dropCount    atomic.Int64
	lastDrainUnix atomic.Int64 // unix seconds
}

// NewManager creates a queue under dir with maxTotal bytes retained (oldest segments removed first).
func NewManager(dir string, maxTotal int64) (*Manager, error) {
	if maxTotal <= 0 {
		maxTotal = 500 << 20
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{dir: dir, maxTotal: maxTotal}
	if err := m.openNextSegment(); err != nil {
		return nil, err
	}
	m.recomputeTotalLocked()
	return m, nil
}

func (m *Manager) openNextSegment() error {
	if m.current != nil {
		_ = m.current.Close()
		m.current = nil
	}
	id := m.seq.Add(1)
	m.currentPath = filepath.Join(m.dir, fmt.Sprintf("seg_%06d.jsonl", id))
	f, err := os.OpenFile(m.currentPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	m.current = f
	m.currentSize = st.Size()
	return nil
}

func (m *Manager) recomputeTotalLocked() {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	var sum int64
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, "seg_") && strings.HasSuffix(n, ".jsonl") {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			sum += fi.Size()
		}
	}
	m.totalBytes = sum
}

func (m *Manager) listSegmentPaths() []string {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, "seg_") && strings.HasSuffix(n, ".jsonl") {
			out = append(out, filepath.Join(m.dir, n))
		}
	}
	sort.Strings(out)
	return out
}

func (m *Manager) evictOldestWhileOverCap() {
	for m.totalBytes > m.maxTotal {
		paths := m.listSegmentPaths()
		var victim string
		for _, p := range paths {
			if p != m.currentPath {
				victim = p
				break
			}
		}
		if victim == "" {
			break
		}
		st, err := os.Stat(victim)
		if err != nil {
			break
		}
		_ = os.Remove(victim)
		m.dropCount.Add(1)
		m.totalBytes -= st.Size()
		if m.totalBytes < 0 {
			m.totalBytes = 0
		}
	}
}

// Append appends one JSON line (caller must not include raw newlines in payload).
func (m *Manager) Append(line []byte) error {
	if m == nil {
		return nil
	}
	if len(line) == 0 {
		return errors.New("empty line")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		if err := m.openNextSegment(); err != nil {
			return err
		}
	}
	rec := append(line, '\n')
	if m.currentSize+int64(len(rec)) > segmentMax {
		_ = m.current.Close()
		m.current = nil
		if err := m.openNextSegment(); err != nil {
			return err
		}
	}
	_, err := m.current.Write(rec)
	if err != nil {
		return err
	}
	m.currentSize += int64(len(rec))
	m.totalBytes += int64(len(rec))
	m.evictOldestWhileOverCap()
	return nil
}

// Stats returns a snapshot for health reporting.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	m.recomputeTotalLocked()
	tbytes := m.totalBytes
	cur := m.currentPath
	m.mu.Unlock()

	depth := 0
	for _, p := range m.listSegmentPaths() {
		if p == cur {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		c, err := lineCount(f)
		_ = f.Close()
		if err == nil {
			depth += c
		}
	}
	var last time.Time
	if u := m.lastDrainUnix.Load(); u > 0 {
		last = time.Unix(u, 0).UTC()
	}
	return Stats{
		QueueDepth: depth,
		BytesUsed:  tbytes,
		DropCount:  m.dropCount.Load(),
		LastDrain:  last,
	}
}

func lineCount(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
	}
	return n, sc.Err()
}

// DiskQueue wraps Manager for legacy Open() API.
type DiskQueue struct{ *Manager }

func Open(baseDir, name string) (*DiskQueue, error) {
	m, err := NewManager(filepath.Join(baseDir, name), 500<<20)
	if err != nil {
		return nil, err
	}
	return &DiskQueue{Manager: m}, nil
}

func (q *DiskQueue) Append(line []byte) error {
	if q == nil || q.Manager == nil {
		return nil
	}
	return q.Manager.Append(line)
}

// HealthPayload is JSON-friendly queue stats.
type HealthPayload struct {
	QueueDepth  int       `json:"queue_depth"`
	BytesUsed   int64     `json:"bytes_used"`
	DropCount   int64     `json:"drop_count"`
	LastDrain   time.Time `json:"last_drain_time,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

func (m *Manager) HealthJSON() ([]byte, error) {
	s := m.Stats()
	return json.Marshal(HealthPayload{
		QueueDepth:  s.QueueDepth,
		BytesUsed:   s.BytesUsed,
		DropCount:   s.DropCount,
		LastDrain:   s.LastDrain,
		GeneratedAt: time.Now().UTC(),
	})
}

// RotateActiveSegment closes the current JSONL segment so the next Append starts
// a new file. Completed segments (other than the active writer) can be drained.
func (m *Manager) RotateActiveSegment() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.openNextSegment(); err != nil {
		return err
	}
	m.recomputeTotalLocked()
	return nil
}

// DrainOldestSegment reads the oldest completed segment, sends each line (spacing
// sends to respect maxPerSec), then removes the file on full success.
func (m *Manager) DrainOldestSegment(ctx context.Context, send func([]byte) error, maxPerSec int) error {
	if maxPerSec <= 0 {
		maxPerSec = 100
	}
	delay := time.Second / time.Duration(maxPerSec)

	m.mu.Lock()
	cur := m.currentPath
	m.mu.Unlock()

	paths := m.listSegmentPaths()
	var target string
	for _, p := range paths {
		if p != cur {
			target = p
			break
		}
	}
	if target == "" {
		return nil
	}
	b, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	buf := make([]byte, 0, 1024)
	sc.Buffer(buf, 4<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(lines) == 0 {
		st0, _ := os.Stat(target)
		var z int64
		if st0 != nil {
			z = st0.Size()
		}
		_ = os.Remove(target)
		m.mu.Lock()
		m.totalBytes -= z
		if m.totalBytes < 0 {
			m.totalBytes = 0
		}
		m.lastDrainUnix.Store(time.Now().Unix())
		m.mu.Unlock()
		return nil
	}
	st, statErr := os.Stat(target)
	var sz int64
	if statErr == nil && st != nil {
		sz = st.Size()
	}
	for i, ln := range lines {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := send(ln); err != nil {
			return err
		}
		if i < len(lines)-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	_ = os.Remove(target)
	m.mu.Lock()
	m.totalBytes -= sz
	if m.totalBytes < 0 {
		m.totalBytes = 0
	}
	m.lastDrainUnix.Store(time.Now().Unix())
	m.mu.Unlock()
	return nil
}
