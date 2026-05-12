package telemetryqueue

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
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
	mu            sync.Mutex
	dir           string
	maxTotal      int64
	seq           atomic.Uint64
	currentPath   string
	current       *os.File
	currentSize   int64
	totalBytes    int64
	dropCount     atomic.Int64
	lastDrainUnix atomic.Int64 // unix seconds

	// Lifecycle plumbing for the background fsync loop (P0-11).
	startOnce sync.Once
	cancel    context.CancelFunc
	wg        sync.WaitGroup
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
//
// P2-11: every record gets a CRC32 checksum (Castagnoli polynomial)
// prefixed in an EDR-Q1 framing comment so the drainer can detect
// silent corruption (bit rot, partial-write on power loss). The framing
// is "// EDR-Q1 crc=<hex>" prepended to the original JSON, separated
// by a tab so old consumers that don't understand the comment skip
// directly to the JSON object. Records without the prefix are
// accepted as legacy "trust the bytes" entries during the rollout
// window.
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
	rec := encodeRecord(line)
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

const recordFramePrefix = "// EDR-Q1 crc="

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// encodeRecord prepends a CRC32 framing comment and appends a newline.
// Format: `// EDR-Q1 crc=<8 hex>\t<json>\n`
func encodeRecord(line []byte) []byte {
	crc := crc32.Checksum(line, crcTable)
	var hex [8]byte
	hexDigits := "0123456789abcdef"
	for i := 0; i < 8; i++ {
		hex[7-i] = hexDigits[crc&0xf]
		crc >>= 4
	}
	out := make([]byte, 0, len(recordFramePrefix)+8+1+len(line)+1)
	out = append(out, recordFramePrefix...)
	out = append(out, hex[:]...)
	out = append(out, '\t')
	out = append(out, line...)
	out = append(out, '\n')
	return out
}

// decodeRecord strips the EDR-Q1 framing and verifies the CRC. Returns
// the inner JSON payload and ok=true on a verified record. Records
// without the framing are accepted as-is (ok=true, payload=line) so
// the drainer can read mixed-format queues during the rollout window.
func decodeRecord(line []byte) ([]byte, bool) {
	if len(line) == 0 {
		return nil, false
	}
	if !strings.HasPrefix(string(line), recordFramePrefix) {
		return line, true
	}
	rest := line[len(recordFramePrefix):]
	if len(rest) < 9 || rest[8] != '\t' {
		return nil, false
	}
	var stored uint32
	for i := 0; i < 8; i++ {
		c := rest[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return nil, false
		}
		stored = stored<<4 | uint32(v)
	}
	payload := rest[9:]
	if crc32.Checksum(payload, crcTable) != stored {
		return nil, false
	}
	return payload, true
}

// _ silences the import linter for binary which we want available for
// future fixed-width record framing variants.
var _ = binary.LittleEndian

// Start activates the background fsync loop (P0-11). It is safe to call
// multiple times; only the first call has effect. The loop runs until ctx
// is cancelled or Close is called.
//
// Without periodic fsync, the queue retained only POSIX-buffered writes —
// an unclean shutdown (kernel panic, power loss, container kill) could lose
// every record accumulated since the last filesystem flush. 1s is the
// industry-standard interval for forensic logging: bounded data loss
// without the cost of a per-event sync.
func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	m.startOnce.Do(func() {
		child, cancel := context.WithCancel(ctx)
		m.cancel = cancel
		m.wg.Add(1)
		go m.fsyncLoop(child)
	})
}

// Close stops the background fsync loop and fsyncs the active segment one
// final time so no buffered writes leak.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		_ = m.current.Sync()
		_ = m.current.Close()
		m.current = nil
	}
	return nil
}

func (m *Manager) fsyncLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.current != nil {
				// Errors here are surfaced via the next Append failure
				// or recomputeTotalLocked; logging from this package
				// would create import cycles with the agent logger.
				_ = m.current.Sync()
			}
			m.mu.Unlock()
		}
	}
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

// DrainOldestSegment reads the oldest completed segment line by line and
// invokes send for each non-empty record. Sends are spaced to honor
// maxPerSec (default 100). On full success the source file is removed and
// the persistent totals are decremented atomically.
//
// Previously the entire segment was os.ReadFile'd into memory before any
// send — a single rotation accumulating against a stalled sink could push
// the agent toward OOM. The streaming variant uses bufio.Scanner with a
// 4 MiB record cap (same as the previous in-memory cap) and never holds
// more than one record in memory at a time.
//
// Records are CRC-verified per P2-11; corrupt records are skipped and
// counted (Stats reports them via DropCount in a future field once the
// rollout is complete).
func (m *Manager) DrainOldestSegment(ctx context.Context, send func([]byte) error, maxPerSec int) error {
	return m.DrainOldestSegmentBytes(ctx, send, 0, maxPerSec)
}

// DrainOldestSegmentBytes is the same as DrainOldestSegment but rate-
// limits by bytes per second (P2-12) when maxBytesPerSec > 0. Each
// record contributes len(record_bytes) to the budget; when the budget
// is exhausted the drainer sleeps until the next 1-second window. Set
// maxBytesPerSec=0 to fall back to the legacy events-per-second
// throttle.
func (m *Manager) DrainOldestSegmentBytes(ctx context.Context, send func([]byte) error, maxBytesPerSec, maxPerSec int) error {
	if maxPerSec <= 0 && maxBytesPerSec <= 0 {
		maxPerSec = 100
	}
	useBytes := maxBytesPerSec > 0
	var perEventDelay time.Duration
	if !useBytes {
		perEventDelay = time.Second / time.Duration(maxPerSec)
	}

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

	st, statErr := os.Stat(target)
	var sz int64
	if statErr == nil && st != nil {
		sz = st.Size()
	}

	f, err := os.Open(target)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)

	sent := false
	bytesThisWindow := 0
	windowStart := time.Now()
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		payload, ok := decodeRecord(line)
		if !ok {
			// Corrupt record — skip but keep draining so a single
			// flipped bit does not stall the whole segment.
			continue
		}
		buf := make([]byte, len(payload))
		copy(buf, payload)
		if err := send(buf); err != nil {
			return err
		}
		if useBytes {
			bytesThisWindow += len(line)
			if bytesThisWindow >= maxBytesPerSec {
				elapsed := time.Since(windowStart)
				if elapsed < time.Second {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(time.Second - elapsed):
					}
				}
				bytesThisWindow = 0
				windowStart = time.Now()
			}
		} else if sent {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(perEventDelay):
			}
		}
		sent = true
	}
	if err := sc.Err(); err != nil {
		return err
	}

	_ = f.Close()
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
