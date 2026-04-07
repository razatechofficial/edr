package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
	"go.uber.org/zap"
)

// YARAMatch represents a YARA rule match.
type YARAMatch struct {
	Rule      string
	Namespace string
	Tags      []string
	Strings   []YARAString
	Meta      map[string]interface{}
}

// YARAString represents a matched string within a YARA rule.
type YARAString struct {
	Name   string
	Offset uint64
	Data   []byte
}

// YARAEngine scans files and memory against compiled YARA rules.
type YARAEngine struct {
	rulesDir    string
	rules       *yara.Rules
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

// LoadRules loads and parses all .yar/.yara files from the configured directory.
func (e *YARAEngine) LoadRules() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("yara: new compiler: %w", err)
	}
	defer compiler.Destroy()

	count := 0
	err = filepath.WalkDir(e.rulesDir, func(path string, d os.DirEntry, walkErr error) error {
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
		f, openErr := os.Open(path)
		if openErr != nil {
			e.logger.Warn("yara: failed to open rule file", zap.String("path", path), zap.Error(openErr))
			return nil
		}
		defer f.Close()
		if addErr := compiler.AddFile(f, filepath.Base(filepath.Dir(path))); addErr != nil {
			e.logger.Warn("yara: compile error", zap.String("path", path), zap.Error(addErr))
			return nil
		}
		count++
		return nil
	})
	if err != nil {
		return fmt.Errorf("yara: walk rules: %w", err)
	}
	compiled, err := compiler.GetRules()
	if err != nil {
		return fmt.Errorf("yara: get compiled rules: %w", err)
	}

	e.mu.Lock()
	if e.rules != nil {
		e.rules.Destroy()
	}
	e.rules = compiled
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
	r := e.rules
	timeout := e.timeout
	e.mu.RUnlock()
	if r == nil {
		return nil, fmt.Errorf("yara: no rules loaded")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < timeout {
			timeout = d
		}
	}
	m := yara.MatchRules{}
	if err := r.ScanFile(path, 0, timeout, &m); err != nil {
		return nil, fmt.Errorf("yara: scan file %s: %w", path, err)
	}
	return convertMatches(m), nil
}

// ScanBytes scans in-memory data against all compiled rules.
func (e *YARAEngine) ScanBytes(ctx context.Context, data []byte) ([]YARAMatch, error) {
	e.mu.RLock()
	r := e.rules
	timeout := e.timeout
	e.mu.RUnlock()
	if r == nil {
		return nil, fmt.Errorf("yara: no rules loaded")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < timeout {
			timeout = d
		}
	}
	m := yara.MatchRules{}
	if err := r.ScanMem(data, 0, timeout, &m); err != nil {
		return nil, fmt.Errorf("yara: scan bytes: %w", err)
	}
	return convertMatches(m), nil
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
	if e.rules == nil {
		e.mu.RUnlock()
		return 0
	}
	n := len(e.rules.GetRules())
	e.mu.RUnlock()
	return n
}

// Stop drains the worker pool and releases resources.
func (e *YARAEngine) Stop() error {
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	e.mu.Lock()
	if e.rules != nil {
		e.rules.Destroy()
		e.rules = nil
	}
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
