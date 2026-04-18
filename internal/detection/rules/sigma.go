package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sigma "github.com/bradleyjkemp/sigma-go"
	sigmaeval "github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/events"
)

// SigmaEngine evaluates events against Sigma detection rules.
type SigmaEngine struct {
	rulesDir   string
	evaluators []*sigmaeval.RuleEvaluator
	enabled    map[string]bool
	mapper     *MITREMapper
	mu         sync.RWMutex
	logger     *zap.Logger
	watcher    *fsnotify.Watcher
	cancelFunc context.CancelFunc
}

// NewSigmaEngine loads all .yml/.yaml Sigma rules from rulesDir and prepares
// them for evaluation.
func NewSigmaEngine(rulesDir string, logger *zap.Logger) (*SigmaEngine, error) {
	info, err := os.Stat(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("sigma: rules directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("sigma: %s is not a directory", rulesDir)
	}

	e := &SigmaEngine{
		rulesDir: rulesDir,
		enabled:  make(map[string]bool),
		mapper:   NewMITREMapper(),
		logger:   logger,
	}
	if err := e.LoadRules(); err != nil {
		return nil, err
	}
	return e, nil
}

// LoadRules parses all Sigma YAML files under the configured directory (recursively)
// and compiles them into evaluators. Existing rules are replaced atomically.
func (e *SigmaEngine) LoadRules() error {
	var files []string
	err := filepath.WalkDir(e.rulesDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yml", ".yaml":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("sigma: walk rules dir: %w", err)
	}

	evaluators := make([]*sigmaeval.RuleEvaluator, 0, len(files))
	var parseErrors int
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			e.logger.Warn("sigma: failed to read rule file", zap.String("path", f), zap.Error(err))
			parseErrors++
			continue
		}

		rule, err := sigma.ParseRule(data)
		if err != nil {
			e.logger.Warn("sigma: failed to parse rule", zap.String("path", f), zap.Error(err))
			parseErrors++
			continue
		}

		evaluators = append(evaluators, sigmaeval.ForRule(rule))
	}

	e.mu.Lock()
	e.evaluators = evaluators
	for _, ev := range evaluators {
		if _, ok := e.enabled[ev.ID]; !ok {
			e.enabled[ev.ID] = true
		}
	}
	e.mu.Unlock()

	e.logger.Info("sigma: rules loaded",
		zap.Int("loaded", len(evaluators)),
		zap.Int("errors", parseErrors),
	)
	return nil
}

// Evaluate tests an event (as a flat key-value map) against every loaded
// Sigma rule and returns alerts for all matches.
func (e *SigmaEngine) Evaluate(event map[string]interface{}) []*events.Alert {
	e.mu.RLock()
	evals := e.evaluators
	e.mu.RUnlock()

	var alerts []*events.Alert
	ctx := context.Background()

	for _, eval := range evals {
		e.mu.RLock()
		enabled := e.enabled[eval.ID]
		e.mu.RUnlock()
		if !enabled {
			continue
		}
		result, err := eval.Matches(ctx, event)
		if err != nil {
			e.logger.Debug("sigma: evaluation error",
				zap.String("rule", eval.Title),
				zap.Error(err),
			)
			continue
		}
		if !result.Match {
			continue
		}

		alert := &events.Alert{
			ID:          uuid.New().String(),
			RuleID:      eval.ID,
			RuleName:    eval.Title,
			Severity:    mapSigmaLevel(eval.Level),
			Title:       eval.Title,
			Description: eval.Description,
			Timestamp:   time.Now().UTC(),
			Tags:        eval.Tags,
			RawEvent:    event,
		}

		for _, tag := range eval.Tags {
			if m := e.mapper.MapSigmaTag(tag); m != nil {
				alert.MITRE = append(alert.MITRE, *m)
			}
		}
		alerts = append(alerts, alert)
	}
	return alerts
}

// SetRuleEnabled toggles a specific Sigma rule by ID at runtime.
func (e *SigmaEngine) SetRuleEnabled(ruleID string, enabled bool) {
	e.mu.Lock()
	e.enabled[ruleID] = enabled
	e.mu.Unlock()
}

// EnabledRuleCount returns number of currently enabled rules.
func (e *SigmaEngine) EnabledRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, ev := range e.evaluators {
		if e.enabled[ev.ID] {
			n++
		}
	}
	return n
}

// EventToMap converts a typed event struct (e.g., ProcessEvent, FileEvent,
// NetworkEvent) into the flat map[string]interface{} required by Sigma evaluation.
// It uses JSON round-tripping so any struct with json tags is supported.
func EventToMap(event interface{}) map[string]interface{} {
	if event == nil {
		return nil
	}
	if m, ok := event.(map[string]interface{}); ok {
		return m
	}

	data, err := json.Marshal(event)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// WatchAndReload watches the rules directory for file changes and reloads
// rules automatically. It blocks until the context is cancelled.
func (e *SigmaEngine) WatchAndReload(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("sigma: create watcher: %w", err)
	}
	if err := watcher.Add(e.rulesDir); err != nil {
		watcher.Close()
		return fmt.Errorf("sigma: watch directory: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	e.mu.Lock()
	e.watcher = watcher
	e.cancelFunc = cancel
	e.mu.Unlock()

	const debounce = 500 * time.Millisecond
	var timer *time.Timer

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()

		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(ev.Name))
			if ext != ".yml" && ext != ".yaml" {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(debounce, func() {
				if err := e.LoadRules(); err != nil {
					e.logger.Error("sigma: hot-reload failed", zap.Error(err))
				}
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			e.logger.Error("sigma: watcher error", zap.Error(err))
		}
	}
}

// Count returns the number of currently loaded Sigma rules.
func (e *SigmaEngine) Count() int {
	e.mu.RLock()
	n := len(e.evaluators)
	e.mu.RUnlock()
	return n
}

// Stop cancels the directory watcher and releases resources.
func (e *SigmaEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cancelFunc != nil {
		e.cancelFunc()
		e.cancelFunc = nil
	}
	if e.watcher != nil {
		err := e.watcher.Close()
		e.watcher = nil
		return err
	}
	return nil
}

func mapSigmaLevel(level string) events.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return events.SeverityCritical
	case "high":
		return events.SeverityHigh
	case "medium":
		return events.SeverityMedium
	case "low":
		return events.SeverityLow
	default:
		return events.SeverityInfo
	}
}
