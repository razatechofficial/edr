package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sigma "github.com/bradleyjkemp/sigma-go"
	sigmaeval "github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/events"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

// compiledSigmaSet is swapped atomically on successful reload.
type compiledSigmaSet struct {
	evaluators  []*sigmaeval.RuleEvaluator
	enabled     map[string]bool
	byCategory  map[string][]*sigmaeval.RuleEvaluator
}

// SigmaEngine evaluates events against Sigma detection rules.
type SigmaEngine struct {
	rulesDir   string
	current    atomic.Pointer[compiledSigmaSet]
	mapper     *MITREMapper
	mu         sync.Mutex
	logger     *zap.Logger
	watcher    *fsnotify.Watcher
	cancelFunc context.CancelFunc
	regexCache sync.Map
}

var sigmaFieldMap = map[string]string{
	"ImagePath":      "Image",
	"ProcessPath":    "Image",
	"CommandLine":    "CommandLine",
	"ProcessName":    "Image",
	"ParentName":     "ParentImage",
	"DstIP":          "DestinationIp",
	"DstPort":        "DestinationPort",
	"SrcIP":          "SourceIp",
	"Path":           "TargetFilename",
	"RegistryPath":   "TargetObject",
	"RegistryValue":  "Details",
	"Operation":      "EventType",
	"DNSQuery":       "QueryName",
	"ProcessHashSHA": "Hashes",
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
		mapper:   NewMITREMapper(),
		logger:   logger,
	}
	if err := e.LoadRules(); err != nil {
		return nil, err
	}
	return e, nil
}

// LoadRules builds a new compiledSigmaSet in memory and atomically replaces
// the current set on success. An empty new compile does not clobber a prior set.
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

	if len(evaluators) == 0 {
		e.mu.Lock()
		had := e.current.Load() != nil
		e.mu.Unlock()
		if had {
			return fmt.Errorf("sigma: reload produced zero rules; keeping previous set")
		}
		return fmt.Errorf("sigma: no rules could be loaded")
	}

	e.mu.Lock()
	old := e.current.Load()
	enabled := make(map[string]bool)
	if old != nil {
		for k, v := range old.enabled {
			enabled[k] = v
		}
	}
	for _, ev := range evaluators {
		if _, ok := enabled[ev.ID]; !ok {
			enabled[ev.ID] = true
		}
	}
	byCategory := buildSigmaCategoryIndex(evaluators)
	set := &compiledSigmaSet{
		evaluators: evaluators,
		enabled:    enabled,
		byCategory: byCategory,
	}
	e.current.Store(set)
	e.warmRegexCache()
	e.mu.Unlock()

	e.logger.Info("sigma: rules loaded",
		zap.Int("loaded", len(evaluators)),
		zap.Int("errors", parseErrors),
	)
	return nil
}

func buildSigmaCategoryIndex(evals []*sigmaeval.RuleEvaluator) map[string][]*sigmaeval.RuleEvaluator {
	out := make(map[string][]*sigmaeval.RuleEvaluator)
	for _, ev := range evals {
		cat := strings.ToLower(strings.TrimSpace(ev.Logsource.Category))
		if cat == "" {
			cat = "_uncat"
		}
		out[cat] = append(out[cat], ev)
	}
	return out
}

func sigmaEvaluatorsForCategory(set *compiledSigmaSet, cat string) []*sigmaeval.RuleEvaluator {
	if set == nil {
		return nil
	}
	if cat == "" {
		return set.evaluators
	}
	seen := make(map[string]struct{}, len(set.evaluators))
	var out []*sigmaeval.RuleEvaluator
	add := func(list []*sigmaeval.RuleEvaluator) {
		for _, ev := range list {
			if ev == nil {
				continue
			}
			if _, ok := seen[ev.ID]; ok {
				continue
			}
			seen[ev.ID] = struct{}{}
			out = append(out, ev)
		}
	}
	add(set.byCategory[cat])
	add(set.byCategory["_uncat"])
	if len(out) == 0 {
		return set.evaluators
	}
	return out
}

// sigmaEventCategory maps normalized telemetry to a Sigma logsource category.
func sigmaEventCategory(m map[string]interface{}) string {
	action := strings.ToLower(stringField(m, "event.action", "esf_op"))
	switch action {
	case "signal":
		return "process_signal"
	case "xpc_connect":
		return "xpc_connection"
	}
	if sub := stringField(m, "subsystem"); sub != "" {
		switch sub {
		case "com.apple.sudo":
			return "sudo"
		case "com.apple.TCC":
			if cat := strings.ToLower(stringField(m, "category")); cat != "" {
				return cat
			}
			return "tcc"
		case "com.apple.xpc":
			return "xpc"
		case "com.apple.syspolicy":
			return "syspolicy"
		case "com.apple.launchd":
			return "launchd"
		case "com.apple.security.assessment":
			return "gatekeeper"
		case "com.apple.alf":
			return "firewall_events"
		case "com.apple.authorization":
			return "authorization"
		}
	}
	if cat := strings.ToLower(stringField(m, "category")); cat != "" {
		return cat
	}
	t := strings.ToLower(stringField(m, "event_type", "type"))
	switch t {
	case "process":
		return "process_creation"
	case "file":
		return "file_event"
	case "network":
		return "network_connection"
	case "registry":
		return "registry_set"
	case "auth", "authentication":
		return "authentication"
	case "file_access":
		return "file_access"
	default:
		return ""
	}
}

// Evaluate tests an event (as a flat key-value map) against loaded rules.
func (e *SigmaEngine) Evaluate(event map[string]interface{}) []*events.Alert {
	event = normalizeSigmaEvent(event)
	set := e.current.Load()
	if set == nil {
		return nil
	}
	cat := sigmaEventCategory(event)
	evals := sigmaEvaluatorsForCategory(set, cat)

	var alerts []*events.Alert
	ctx := context.Background()
	for _, eval := range evals {
		if !set.enabled[eval.ID] {
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

// stringField is a local duplicate for logsource-style lookups without importing detection.
func stringField(m map[string]interface{}, keys ...string) string {
	for _, want := range keys {
		for k, v := range m {
			if strings.EqualFold(k, want) {
				return fmt.Sprint(v)
			}
		}
	}
	return ""
}

func normalizeSigmaEvent(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]interface{}, len(in)+8)
	for k, v := range in {
		out[k] = v
		if mapped, ok := sigmaFieldMap[k]; ok {
			if _, exists := out[mapped]; !exists {
				out[mapped] = v
			}
		}
	}
	return out
}

func (e *SigmaEngine) warmRegexCache() {
	_, _ = e.cachedRegex(`.*`)
}

func (e *SigmaEngine) cachedRegex(expr string) (*regexp.Regexp, error) {
	if v, ok := e.regexCache.Load(expr); ok {
		return v.(*regexp.Regexp), nil
	}
	rx, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	e.regexCache.Store(expr, rx)
	return rx, nil
}

// SetRuleEnabled toggles a specific Sigma rule by ID (copy-on-write on the set).
func (e *SigmaEngine) SetRuleEnabled(ruleID string, on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.current.Load()
	if old == nil {
		return
	}
	en := make(map[string]bool, len(old.enabled)+1)
	for k, v := range old.enabled {
		en[k] = v
	}
	en[ruleID] = on
	e.current.Store(&compiledSigmaSet{
		evaluators: old.evaluators,
		enabled:    en,
		byCategory: old.byCategory,
	})
}

// EnabledRuleCount returns number of currently enabled rules.
func (e *SigmaEngine) EnabledRuleCount() int {
	set := e.current.Load()
	if set == nil {
		return 0
	}
	n := 0
	for _, ev := range set.evaluators {
		if set.enabled[ev.ID] {
			n++
		}
	}
	return n
}

// EventToMap converts a typed event struct to a flat map with Sigma field
// aliases and OCSF detection enrichments applied.
func EventToMap(event interface{}) map[string]interface{} {
	if event == nil {
		return nil
	}
	if m, ok := event.(map[string]interface{}); ok {
		m = normalizeSigmaEvent(m)
		return ocsf.EnrichDetectionMap(m)
	}

	data, err := json.Marshal(event)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	m = normalizeSigmaEvent(m)
	return ocsf.EnrichDetectionMap(m)
}

// WatchAndReload watches the rules directory for file changes and reloads.
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
	set := e.current.Load()
	if set == nil {
		return 0
	}
	return len(set.evaluators)
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
