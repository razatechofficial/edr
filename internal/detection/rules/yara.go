package rules

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

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

// YARAEngine scans files and memory against YARA rules.
//
// This implementation provides a pure-Go fallback that extracts ASCII string
// patterns from YARA source files and matches them with bytes.Contains.
// A production Linux build would replace this with cgo bindings to libyara
// for full YARA semantics including hex patterns, regex, and conditions.
type YARAEngine struct {
	rulesDir    string
	rules       []parsedYARARule
	maxFileSize int64
	workerCount int
	scanChan    chan scanRequest
	logger      *zap.Logger
	mu          sync.RWMutex
	cancelFunc  context.CancelFunc
}

type scanRequest struct {
	path     string
	data     []byte
	resultCh chan<- []YARAMatch
}

type parsedYARARule struct {
	name      string
	tags      []string
	meta      map[string]string
	strings   map[string][]byte // $identifier -> pattern
	condition string
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
	var files []string
	for _, ext := range []string{"*.yar", "*.yara"} {
		matches, err := filepath.Glob(filepath.Join(e.rulesDir, ext))
		if err != nil {
			return fmt.Errorf("yara: glob %s: %w", ext, err)
		}
		files = append(files, matches...)
	}

	var rules []parsedYARARule
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			e.logger.Warn("yara: failed to read rule file", zap.String("path", f), zap.Error(err))
			continue
		}
		parsed, err := parseYARARules(data)
		if err != nil {
			e.logger.Warn("yara: parse error", zap.String("path", f), zap.Error(err))
			continue
		}
		rules = append(rules, parsed...)
	}

	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()

	e.logger.Info("yara: rules loaded", zap.Int("count", len(rules)))
	return nil
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

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("yara: read %s: %w", path, err)
	}
	return e.scanData(ctx, data)
}

// ScanBytes scans in-memory data against all compiled rules.
func (e *YARAEngine) ScanBytes(ctx context.Context, data []byte) ([]YARAMatch, error) {
	return e.scanData(ctx, data)
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
	n := len(e.rules)
	e.mu.RUnlock()
	return n
}

// Stop drains the worker pool and releases resources.
func (e *YARAEngine) Stop() error {
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
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
				matches, _ = e.scanData(ctx, req.data)
			} else if req.path != "" {
				matches, _ = e.ScanFile(ctx, req.path)
			}
			req.resultCh <- matches
		}
	}
}

func (e *YARAEngine) scanData(ctx context.Context, data []byte) ([]YARAMatch, error) {
	e.mu.RLock()
	snapshot := e.rules
	e.mu.RUnlock()

	var matches []YARAMatch
	for _, rule := range snapshot {
		select {
		case <-ctx.Done():
			return matches, ctx.Err()
		default:
		}

		matched := e.matchRule(rule, data)
		if len(matched) == 0 {
			continue
		}

		meta := make(map[string]interface{}, len(rule.meta))
		for k, v := range rule.meta {
			meta[k] = v
		}

		matches = append(matches, YARAMatch{
			Rule:    rule.name,
			Tags:    rule.tags,
			Strings: matched,
			Meta:    meta,
		})
	}
	return matches, nil
}

// matchRule performs degraded pattern matching: for each string defined in the
// rule, check whether the data contains that pattern. The condition field is
// interpreted in a simplified manner (any/all of them).
func (e *YARAEngine) matchRule(rule parsedYARARule, data []byte) []YARAString {
	if len(rule.strings) == 0 {
		return nil
	}

	var hits []YARAString
	for name, pattern := range rule.strings {
		if idx := bytes.Index(data, pattern); idx >= 0 {
			hits = append(hits, YARAString{
				Name:   name,
				Offset: uint64(idx),
				Data:   pattern,
			})
		}
	}

	cond := strings.TrimSpace(strings.ToLower(rule.condition))
	switch {
	case strings.Contains(cond, "all of them"):
		if len(hits) < len(rule.strings) {
			return nil
		}
		return hits
	default:
		// "any of them", "any of ($s*)", or unrecognised → match if any string hit.
		if len(hits) > 0 {
			return hits
		}
		return nil
	}
}

// ---------- YARA source parser (pure-Go, degraded) ----------

var (
	yaraRuleHeader  = regexp.MustCompile(`(?m)^\s*rule\s+(\w+)\s*(?::\s*([\w\s]+))?\s*\{`)
	yaraStringDef   = regexp.MustCompile(`\$(\w+)\s*=\s*"([^"]*)"`)
	yaraMetaDef     = regexp.MustCompile(`(\w+)\s*=\s*"([^"]*)"`)
	yaraSectionHead = regexp.MustCompile(`(?m)^\s*(meta|strings|condition)\s*:`)
)

func parseYARARules(src []byte) ([]parsedYARARule, error) {
	var rules []parsedYARARule
	scanner := bufio.NewScanner(bytes.NewReader(src))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		current   *parsedYARARule
		section   string
		condBuf   strings.Builder
		braceOpen int
	)

	flush := func() {
		if current == nil {
			return
		}
		current.condition = strings.TrimSpace(condBuf.String())
		rules = append(rules, *current)
		current = nil
		section = ""
		condBuf.Reset()
		braceOpen = 0
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if current == nil {
			if m := yaraRuleHeader.FindStringSubmatch(line); m != nil {
				current = &parsedYARARule{
					name:    m[1],
					strings: make(map[string][]byte),
					meta:    make(map[string]string),
				}
				if m[2] != "" {
					for _, t := range strings.Fields(m[2]) {
						current.tags = append(current.tags, t)
					}
				}
				braceOpen = 1
			}
			continue
		}

		braceOpen += strings.Count(line, "{") - strings.Count(line, "}")
		if braceOpen <= 0 {
			flush()
			continue
		}

		if loc := yaraSectionHead.FindStringSubmatch(trimmed); loc != nil {
			section = loc[1]
			continue
		}

		switch section {
		case "meta":
			if m := yaraMetaDef.FindStringSubmatch(trimmed); m != nil {
				current.meta[m[1]] = m[2]
			}
		case "strings":
			if m := yaraStringDef.FindStringSubmatch(trimmed); m != nil {
				current.strings["$"+m[1]] = []byte(m[2])
			}
		case "condition":
			if condBuf.Len() > 0 {
				condBuf.WriteByte(' ')
			}
			condBuf.WriteString(trimmed)
		}
	}
	flush()

	if err := scanner.Err(); err != nil && err != io.EOF {
		return rules, fmt.Errorf("yara: scan: %w", err)
	}
	return rules, nil
}
