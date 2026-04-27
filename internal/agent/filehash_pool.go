package agent

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/schema"
)

const (
	fileHashWorkers     = 2
	fileHashJobQueue    = 512
	fileHashCacheMax    = 2048
	fileHashMaxFileSize = 16 << 20
)

// fileHashPool hashes file telemetry asynchronously with an LRU (path+mtime+size) → SHA256 cache.
type fileHashPool struct {
	jobs  chan *schema.FileEvent
	wg    sync.WaitGroup
	cache *fileHashLRU
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
	p := &fileHashPool{
		jobs:  make(chan *schema.FileEvent, fileHashJobQueue),
		cache: newFileHashLRU(fileHashCacheMax),
	}
	for i := 0; i < fileHashWorkers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

func (p *fileHashPool) Submit(fe *schema.FileEvent) {
	if fe == nil {
		return
	}
	op := strings.ToLower(strings.TrimSpace(fe.Operation))
	if op != "write" && op != "create" {
		return
	}
	if fe.Path == "" {
		return
	}
	select {
	case p.jobs <- fe:
	default:
		// Queue saturated; skip hashing to avoid blocking the pipeline.
	}
}

func (p *fileHashPool) worker() {
	defer p.wg.Done()
	for fe := range p.jobs {
		p.hashOne(fe)
	}
}

func (p *fileHashPool) hashOne(fe *schema.FileEvent) {
	fi, err := os.Stat(fe.Path)
	if err != nil || fi.IsDir() || fi.Size() == 0 || fi.Size() > fileHashMaxFileSize {
		return
	}
	key := fmt.Sprintf("%s|%d|%d", fe.Path, fi.Size(), fi.ModTime().UnixNano())
	if h, ok := p.cache.get(key); ok {
		fe.Hash = h
		p.tryImpHash(fe)
		return
	}
	f, err := os.Open(fe.Path)
	if err != nil {
		return
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	p.cache.put(key, sum)
	fe.Hash = sum
	p.tryImpHash(fe)
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
