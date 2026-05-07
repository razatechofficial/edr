package forensics

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// FIMDiffConfig gates optional unified-diff emission on FIM modify events.
type FIMDiffConfig struct {
	Enabled       bool     `yaml:"fim_diff_enabled" env:"EDR_FORENSICS_FIM_DIFF"`
	MaxFileBytes  int      `yaml:"fim_diff_max_file_bytes" env:"EDR_FORENSICS_FIM_DIFF_MAX_BYTES"`
	PathGlobs     []string `yaml:"fim_diff_path_globs"`
}

// Any reports whether diffing should run.
func (c FIMDiffConfig) Any() bool {
	if !c.Enabled || len(c.PathGlobs) == 0 {
		return false
	}
	return true
}

// FIMDiffCache stores capped prior content per path (LRU-ish eviction).
type FIMDiffCache struct {
	mu       sync.Mutex
	maxFiles int
	maxBytes int
	globs    []string
	entries  map[string]fimSnap
	order    []string
	emits    atomic.Uint64
}

type fimSnap struct {
	sha  string
	text string
}

// NewFIMDiffCache builds a cache; maxFiles defaults to 512.
func NewFIMDiffCache(cfg FIMDiffConfig) *FIMDiffCache {
	if !cfg.Any() {
		return nil
	}
	mb := cfg.MaxFileBytes
	if mb <= 0 {
		mb = 64 * 1024
	}
	return &FIMDiffCache{
		maxFiles: 512,
		maxBytes: mb,
		globs:    cfg.PathGlobs,
		entries:  make(map[string]fimSnap),
	}
}

func (c *FIMDiffCache) pathMatches(path string) bool {
	if c == nil {
		return false
	}
	for _, g := range c.globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if ok, _ := filepath.Match(g, path); ok {
			return true
		}
	}
	return false
}

// DiffOnModify returns a base64 unified diff if the file changed and is within size budget.
func (c *FIMDiffCache) DiffOnModify(path string, read func() ([]byte, error)) (b64 string, err error) {
	if c == nil || !c.pathMatches(path) {
		return "", nil
	}
	b, err := read()
	if err != nil {
		return "", err
	}
	if len(b) > c.maxBytes {
		return "", nil
	}
	h := sha256.Sum256(b)
	cur := fmt.Sprintf("%x", h[:])
	s := string(b)

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, ok := c.entries[path]
	if ok && prev.sha == cur {
		return "", nil
	}

	var diff string
	if ok {
		diff = simpleUnifiedDiff(path, prev.text, s)
	}
	c.touchLocked(path, cur, s)
	if diff == "" {
		return "", nil
	}
	if len(diff) > c.maxBytes {
		diff = diff[:c.maxBytes]
	}
	c.emits.Add(1)
	return base64.StdEncoding.EncodeToString([]byte(diff)), nil
}

// TrackedFiles returns the number of paths retained in the LRU cache.
func (c *FIMDiffCache) TrackedFiles() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	return n
}

// EmitsTotal counts non-empty unified diffs returned from DiffOnModify.
func (c *FIMDiffCache) EmitsTotal() uint64 {
	if c == nil {
		return 0
	}
	return c.emits.Load()
}

func (c *FIMDiffCache) touchLocked(path, sha, text string) {
	for i, k := range c.order {
		if k == path {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, path)
	c.entries[path] = fimSnap{sha: sha, text: text}
	for len(c.order) > c.maxFiles {
		ev := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, ev)
	}
}

func simpleUnifiedDiff(path, a, b string) string {
	la := strings.Split(a, "\n")
	lb := strings.Split(b, "\n")
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- %s\n+++ %s\n", path, path)
	max := len(la)
	if len(lb) > max {
		max = len(lb)
	}
	for i := 0; i < max; i++ {
		var al, bl string
		if i < len(la) {
			al = la[i]
		}
		if i < len(lb) {
			bl = lb[i]
		}
		if al == bl {
			continue
		}
		if al != "" {
			fmt.Fprintf(&buf, "-%s\n", al)
		}
		if bl != "" {
			fmt.Fprintf(&buf, "+%s\n", bl)
		}
	}
	if buf.Len() == 0 {
		return ""
	}
	return buf.String()
}
