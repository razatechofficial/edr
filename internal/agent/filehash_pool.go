package agent

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/schema"
)

const (
	fileHashWorkers      = 2
	fileHashJobQueue     = 512
	fileHashCacheMax     = 2048
	fileHashMaxFileSize  = 16 << 20
	// P1-17: per-file hash deadline. Large or pathological IO (network
	// filesystems, network drives, locked AV-quarantined files) must
	// not stall a hashing worker forever.
	fileHashTimeoutPerOp = 5 * time.Second
)

// fileHashPool hashes file telemetry asynchronously with an LRU
// (path+mtime+size) → SHA256 cache. Each hash operation is bounded by
// fileHashTimeoutPerOp so a single stuck file cannot starve the
// workers. P1-17.
type fileHashPool struct {
	jobs     chan *schema.FileEvent
	wg       sync.WaitGroup
	cache    *fileHashLRU
	closed   atomic.Bool
	closeCh  chan struct{}

	submitted atomic.Uint64
	hashed    atomic.Uint64
	cacheHits atomic.Uint64
	timeouts  atomic.Uint64
	dropped   atomic.Uint64
	// completed counts how many jobs the worker has finished processing
	// (including those that returned early because the file was missing
	// or too large). The atomic store after the fe.Hash assignment
	// inside hashOne is the synchronization edge that lets external
	// callers observe the hash without a data race — see WaitForIdle.
	completed atomic.Uint64
}

type fileHashLRU struct {
	mu    sync.Mutex
	n     int
	max   int
	items map[string]*list.Element
	lru   *list.List
}

type fileHashLRUEntry struct {
	key string
	val string
}

func newFileHashLRU(max int) *fileHashLRU {
	return &fileHashLRU{
		max:   max,
		items: make(map[string]*list.Element),
		lru:   list.New(),
	}
}

func (c *fileHashLRU) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*fileHashLRUEntry).val, true
	}
	return "", false
}

func (c *fileHashLRU) put(key, val string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*fileHashLRUEntry).val = val
		c.lru.MoveToFront(el)
		return
	}
	for c.n >= c.max && c.lru.Len() > 0 {
		back := c.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*fileHashLRUEntry)
		delete(c.items, old.key)
		c.lru.Remove(back)
		c.n--
	}
	e := &fileHashLRUEntry{key: key, val: val}
	el := c.lru.PushFront(e)
	c.items[key] = el
	c.n++
}

func newFileHashPool() *fileHashPool {
	return newFileHashPoolN(fileHashWorkers, fileHashCacheMax)
}

// newFileHashPoolN constructs a pool with explicit worker count and
// cache capacity. Used by tests and by callers that want to scale the
// pool independently of the package default (e.g. a CI agent with
// abundant CPU).
func newFileHashPoolN(workers, cacheMax int) *fileHashPool {
	if workers < 1 {
		workers = 1
	}
	if cacheMax < 1 {
		cacheMax = fileHashCacheMax
	}
	p := &fileHashPool{
		jobs:    make(chan *schema.FileEvent, fileHashJobQueue),
		cache:   newFileHashLRU(cacheMax),
		closeCh: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

// Close stops accepting new jobs, drains the queue, and waits for all
// workers to exit. Safe to call multiple times.
func (p *fileHashPool) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	close(p.jobs)
	p.wg.Wait()
	close(p.closeCh)
}

func (p *fileHashPool) Submit(fe *schema.FileEvent) {
	if fe == nil || p.closed.Load() {
		return
	}
	op := strings.ToLower(strings.TrimSpace(fe.Operation))
	if op != "write" && op != "create" {
		return
	}
	if fe.Path == "" {
		return
	}
	p.submitted.Add(1)
	select {
	case p.jobs <- fe:
	default:
		// Queue saturated; skip hashing to avoid blocking the pipeline.
		p.dropped.Add(1)
	}
}

func (p *fileHashPool) worker() {
	defer p.wg.Done()
	for fe := range p.jobs {
		p.hashOne(fe)
		// Atomic.Add publishes a release barrier so any caller that
		// loads `completed` afterwards (e.g. WaitForIdle) is
		// guaranteed to observe the fe.Hash write performed inside
		// hashOne. This pairs with the atomic.Load on the test
		// side and keeps the race detector silent.
		p.completed.Add(1)
	}
}

func (p *fileHashPool) hashOne(fe *schema.FileEvent) {
	fi, err := os.Stat(fe.Path)
	if err != nil || fi.IsDir() || fi.Size() == 0 || fi.Size() > fileHashMaxFileSize {
		return
	}
	key := fmt.Sprintf("%s|%d|%d", fe.Path, fi.Size(), fi.ModTime().UnixNano())
	if h, ok := p.cache.get(key); ok {
		p.cacheHits.Add(1)
		fe.Hash = h
		p.tryImpHash(fe)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), fileHashTimeoutPerOp)
	defer cancel()
	sum, err := hashFileWithTimeout(ctx, fe.Path)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			p.timeouts.Add(1)
		}
		return
	}
	p.cache.put(key, sum)
	p.hashed.Add(1)
	fe.Hash = sum
	p.tryImpHash(fe)
}

// hashFileWithTimeout reads the file in 64 KiB chunks and checks the
// context deadline between reads. The 5s budget is high enough for any
// non-pathological local filesystem yet aborts cleanly for stuck IO.
func hashFileWithTimeout(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return "", rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *fileHashPool) tryImpHash(fe *schema.FileEvent) {
	if runtime.GOOS != "windows" {
		return
	}
	lp := strings.ToLower(fe.Path)
	if !strings.HasSuffix(lp, ".exe") && !strings.HasSuffix(lp, ".dll") {
		return
	}
	if ih, err := collector.ComputeImpHash(fe.Path); err == nil && ih != "" {
		fe.ImpHash = ih
	}
}

// WaitForIdle blocks until every job submitted before the call has
// been processed, or until timeout elapses. Returns true when the
// pool drained in time and false on timeout.
//
// The atomic.Load on `completed` establishes a happens-before
// relationship with the matching atomic.Add inside worker(), so any
// FileEvent.Hash mutations performed by the worker are guaranteed to
// be visible to the caller once WaitForIdle returns true.
//
// This method is intended for tests; production code submits and
// moves on, accepting that the hash may not be populated by the time
// the event is forwarded.
func (p *fileHashPool) WaitForIdle(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		submitted := p.submitted.Load()
		dropped := p.dropped.Load()
		completed := p.completed.Load()
		if completed >= submitted-dropped {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}
