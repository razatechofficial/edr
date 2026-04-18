//go:build cgo

package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
	"go.uber.org/zap"
)

// YARAEngine scans files and memory against compiled YARA rules.
// ruleSets holds one compiled ruleset per successfully parsed .yar file so a
// single broken rule does not poison the whole corpus (YARA compilers cannot
// recover after a parse error).
type YARAEngine struct {
	rulesDir    string
	ruleSets    []*yara.Rules
	maxFileSize int64
	workerCount int
	scanChan    chan scanRequest
	logger      *zap.Logger
	mu          sync.RWMutex
	cancelFunc  context.CancelFunc
	timeout     time.Duration
}

type scanRequest struct {
	path     string
	data     []byte
	resultCh chan<- []YARAMatch
}

// NewYARAEngine creates a YARA scanning engine backed by a worker pool.
func NewYARAEngine(rulesDir string, maxFileSizeMB int, workers int, logger *zap.Logger) (*YARAEngine, error) {
	if workers < 1 {
		workers = 1
	}
	if maxFileSizeMB < 1 {
		maxFileSizeMB = 50
	}

	e := &YARAEngine{
		rulesDir:    rulesDir,
		maxFileSize: int64(maxFileSizeMB) * 1024 * 1024,
		workerCount: workers,
		scanChan:    make(chan scanRequest, workers*4),
		logger:      logger,
		timeout:     5 * time.Second,
	}

	if err := e.LoadRules(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.cancelFunc = cancel
	for i := 0; i < workers; i++ {
		go e.worker(ctx)
	}

	return e, nil
}

// compileOneRuleFile parses a single YARA file into its own ruleset.
func compileOneRuleFile(path, namespace string) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	defer compiler.Destroy()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := compiler.AddFile(f, namespace); err != nil {
		return nil, err
	}
	return compiler.GetRules()
}

// LoadRules loads and parses all .yar/.yara files from the configured directory.
func (e *YARAEngine) LoadRules() error {
	e.mu.Lock()
	for _, rs := range e.ruleSets {
		if rs != nil {
			rs.Destroy()
		}
	}
	e.ruleSets = nil
	e.mu.Unlock()

	var sets []*yara.Rules
	count := 0
	err := filepath.WalkDir(e.rulesDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yar" && ext != ".yara" {
			return nil
		}
		ns := filepath.Base(filepath.Dir(path))
		compiled, compErr := compileOneRuleFile(path, ns)
		if compErr != nil {
			// Libyara often rejects upstream rules with "unreferenced string" (YARA version drift).
			// Skip the file either way; avoid flooding default logs — use --debug to see details.
			msg := strings.ToLower(compErr.Error())
			if strings.Contains(msg, "unreferenced string") {
				e.logger.Debug("yara: skipped rule file", zap.String("path", path), zap.Error(compErr))
			} else {
				e.logger.Warn("yara: compile error", zap.String("path", path), zap.Error(compErr))
			}
			return nil
		}
		sets = append(sets, compiled)
		count++
		return nil
	})
	if err != nil {
		return fmt.Errorf("yara: walk rules: %w", err)
	}
	if len(sets) == 0 {
		return fmt.Errorf("yara: no rules compiled successfully")
	}

	e.mu.Lock()
	e.ruleSets = sets
	e.mu.Unlock()

	e.logger.Info("yara: rules loaded", zap.Int("files", count))
	return nil
}

func convertMatches(in yara.MatchRules) []YARAMatch {
	out := make([]YARAMatch, 0, len(in))
	for _, m := range in {
		meta := make(map[string]interface{}, len(m.Metas))
		for _, mv := range m.Metas {
			meta[mv.Identifier] = mv.Value
		}
		stringsOut := make([]YARAString, 0, len(m.Strings))
		for _, s := range m.Strings {
			stringsOut = append(stringsOut, YARAString{
				Name:   s.Name,
				Offset: s.Offset,
				Data:   s.Data,
			})
		}
		out = append(out, YARAMatch{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Strings:   stringsOut,
			Meta:      meta,
		})
	}
	return out
}

func mergeYARAMatches(a, b []YARAMatch) []YARAMatch {
	out := make([]YARAMatch, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, m := range a {
		key := m.Namespace + "\x00" + m.Rule
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	for _, m := range b {
		key := m.Namespace + "\x00" + m.Rule
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}

// ScanFile scans a file on disk against all compiled rules.
func (e *YARAEngine) ScanFile(ctx context.Context, path string) ([]YARAMatch, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("yara: stat %s: %w", path, err)
	}
	if info.Size() > e.maxFileSize {
		return nil, fmt.Errorf("yara: file %s exceeds max size (%d > %d)", path, info.Size(), e.maxFileSize)
	}

	e.mu.RLock()
	sets := e.ruleSets
	timeout := e.timeout
	e.mu.RUnlock()
	if len(sets) == 0 {
		return nil, fmt.Errorf("yara: no rules loaded")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < timeout {
			timeout = d
		}
	}
	var all []YARAMatch
	for _, r := range sets {
		if r == nil {
			continue
		}
		m := yara.MatchRules{}
		if err := r.ScanFile(path, 0, timeout, &m); err != nil {
			return nil, fmt.Errorf("yara: scan file %s: %w", path, err)
		}
		all = mergeYARAMatches(all, convertMatches(m))
	}
	return all, nil
}

// ScanBytes scans in-memory data against all compiled rules.
func (e *YARAEngine) ScanBytes(ctx context.Context, data []byte) ([]YARAMatch, error) {
	e.mu.RLock()
	sets := e.ruleSets
	timeout := e.timeout
	e.mu.RUnlock()
	if len(sets) == 0 {
		return nil, fmt.Errorf("yara: no rules loaded")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < timeout {
			timeout = d
		}
	}
	var all []YARAMatch
	for _, r := range sets {
		if r == nil {
			continue
		}
		m := yara.MatchRules{}
		if err := r.ScanMem(data, 0, timeout, &m); err != nil {
			return nil, fmt.Errorf("yara: scan bytes: %w", err)
		}
		all = mergeYARAMatches(all, convertMatches(m))
	}
	return all, nil
}

// ScanFileAsync queues a non-blocking file scan and returns a channel that
// will receive the match results when the worker pool processes the request.
func (e *YARAEngine) ScanFileAsync(path string) <-chan []YARAMatch {
	ch := make(chan []YARAMatch, 1)
	e.scanChan <- scanRequest{path: path, resultCh: ch}
	return ch
}

// Count returns the number of loaded YARA rules.
func (e *YARAEngine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, r := range e.ruleSets {
		if r == nil {
			continue
		}
		n += len(r.GetRules())
	}
	return n
}

// Stop drains the worker pool and releases resources.
func (e *YARAEngine) Stop() error {
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	e.mu.Lock()
	for _, rs := range e.ruleSets {
		if rs != nil {
			rs.Destroy()
		}
	}
	e.ruleSets = nil
	e.mu.Unlock()
	close(e.scanChan)
	return nil
}

func (e *YARAEngine) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-e.scanChan:
			if !ok {
				return
			}
			var matches []YARAMatch
			if req.data != nil {
				matches, _ = e.ScanBytes(ctx, req.data)
			} else if req.path != "" {
				matches, _ = e.ScanFile(ctx, req.path)
			}
			req.resultCh <- matches
		}
	}
}
