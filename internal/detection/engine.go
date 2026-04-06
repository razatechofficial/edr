package detection

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/ioc"
	"github.com/razatechofficial/edr/internal/detection/llm"
	"github.com/razatechofficial/edr/internal/detection/ml"
	"github.com/razatechofficial/edr/internal/detection/rules"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
)

// EngineConfig controls which detection layers are active and where their
// data files reside.
type EngineConfig struct {
	IOCEnabled        bool
	SigmaEnabled      bool
	YARAEnabled       bool
	BehavioralEnabled bool
	MLEnabled         bool
	LLMEnabled        bool
	WorkerCount       int

	SigmaRulesDir   string
	YARARulesDir    string
	CustomRulesPath string
	IOCHashDBPath   string
	IOCIPDBPath     string
	IOCDomainDBPath string
	MLModelsDir     string
}

// Engine is the main detection orchestrator that runs events through all
// detection layers concurrently and merges results. Layers that fail to
// initialize or panic at runtime are isolated so the remaining layers
// continue to operate.
type Engine struct {
	ioc        *ioc.Matcher
	sigma      *rules.SigmaEngine
	yara       *rules.YARAEngine
	custom     *rules.CustomEngine
	behavioral []Detector
	correlator *Correlator
	sequencer  *SequenceEngine
	ml         *ml.Engine
	llm        *llm.Engine

	cfg         EngineConfig
	alertCh     chan *events.Alert
	workerCount int
	logger      *zap.Logger

	mu      sync.RWMutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	stopCh  chan struct{}
	llmWg   sync.WaitGroup
}

// NewEngine creates and initializes all detection layers. Layers whose
// configuration is disabled or whose initialization fails are logged and
// skipped so the remaining layers continue to operate.
func NewEngine(cfg EngineConfig, logger *zap.Logger) (*Engine, error) {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 4
	}

	e := &Engine{
		cfg:         cfg,
		workerCount: cfg.WorkerCount,
		alertCh:     make(chan *events.Alert, cfg.WorkerCount*64),
		logger:      logger,
		stopCh:      make(chan struct{}),
	}

	if cfg.IOCEnabled {
		m := ioc.NewMatcher(logger)
		if err := m.LoadAll(cfg.IOCHashDBPath, cfg.IOCIPDBPath, cfg.IOCDomainDBPath); err != nil {
			logger.Warn("engine: ioc layer init failed, disabling", zap.Error(err))
		} else {
			e.ioc = m
		}
	}

	if cfg.YARAEnabled && cfg.YARARulesDir != "" {
		ye, err := rules.NewYARAEngine(cfg.YARARulesDir, 50, cfg.WorkerCount, logger)
		if err != nil {
			logger.Warn("engine: yara layer init failed, disabling", zap.Error(err))
		} else {
			e.yara = ye
		}
	}

	if cfg.SigmaEnabled && cfg.SigmaRulesDir != "" {
		se, err := rules.NewSigmaEngine(cfg.SigmaRulesDir, logger)
		if err != nil {
			logger.Warn("engine: sigma layer init failed, disabling", zap.Error(err))
		} else {
			e.sigma = se
		}
	}

	if cfg.CustomRulesPath != "" {
		ce, err := rules.NewCustomEngine(logger)
		if err != nil {
			logger.Warn("engine: custom rules layer init failed, disabling", zap.Error(err))
		} else if err := ce.LoadRules(cfg.CustomRulesPath); err != nil {
			logger.Warn("engine: custom rules load failed", zap.Error(err))
		} else {
			e.custom = ce
		}
	}

	if cfg.BehavioralEnabled {
		e.correlator = NewCorrelator(logger)
		e.sequencer = NewSequenceEngine(logger)
		e.behavioral = []Detector{
			NewPersistenceDetector(logger),
			NewPrivescDetector(logger),
			NewExfiltrationDetector(logger),
			NewLateralDetector(logger),
			NewCredentialDetector(logger),
			NewInjectionDetector(logger),
			NewRATDetector(logger),
			NewRansomwareDetector(logger),
		}
	}

	if cfg.MLEnabled && cfg.MLModelsDir != "" {
		me, err := ml.NewEngine(cfg.MLModelsDir, logger)
		if err != nil {
			logger.Warn("engine: ml layer init failed, disabling", zap.Error(err))
		} else {
			e.ml = me
		}
	}

	return e, nil
}

// Start launches background workers for rule hot-reloading and marks the
// engine as ready to evaluate events. It returns an error if the engine is
// already running.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("engine: already running")
	}
	ctx, e.cancel = context.WithCancel(ctx)
	e.running = true
	e.mu.Unlock()

	if e.sigma != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.sigma.WatchAndReload(ctx); err != nil && ctx.Err() == nil {
				e.logger.Error("engine: sigma watcher failed", zap.Error(err))
			}
		}()
	}

	e.logger.Info("engine: started",
		zap.Bool("ioc", e.ioc != nil),
		zap.Bool("yara", e.yara != nil),
		zap.Bool("sigma", e.sigma != nil),
		zap.Bool("custom", e.custom != nil),
		zap.Int("behavioral_detectors", len(e.behavioral)),
		zap.Bool("sequencer", e.sequencer != nil),
		zap.Bool("ml", e.ml != nil),
		zap.Bool("llm", e.llm != nil),
	)
	return nil
}

// Stop gracefully shuts down the engine, stopping all background goroutines
// and releasing sub-engine resources. It is safe to call multiple times.
func (e *Engine) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	e.mu.Unlock()

	close(e.stopCh)

	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	e.llmWg.Wait()
	close(e.alertCh)

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.yara != nil {
		record(e.yara.Stop())
	}
	if e.sigma != nil {
		record(e.sigma.Stop())
	}
	if e.correlator != nil {
		e.correlator.Stop()
	}
	return firstErr
}

// Alerts returns a read-only channel that consumers use to receive detection
// alerts produced by all layers, including asynchronous LLM verdicts.
func (e *Engine) Alerts() <-chan *events.Alert {
	return e.alertCh
}

// Evaluate runs the event through all enabled detection layers concurrently
// and returns the merged, deduplicated set of alerts.
//
// Layer execution (1-5 concurrent, 6 async fire-and-forget):
//   - Layer 1 (IOC): hash, IP, domain lookups (<1ms target)
//   - Layer 2 (YARA): file scanning for file events (<5ms target)
//   - Layer 3 (Sigma + Custom CEL): rule evaluation (<2ms target)
//   - Layer 4 (Behavioral): 8 detectors + correlator + sequencer (<10ms target)
//   - Layer 5 (ML): model inference when applicable (<15ms target)
//   - Layer 6 (LLM): async deep analysis if layers 1-5 produced medium+ severity
func (e *Engine) Evaluate(ctx context.Context, event interface{}) []*events.Alert {
	e.mu.RLock()
	if !e.running {
		e.mu.RUnlock()
		return nil
	}
	e.mu.RUnlock()

	var (
		resultMu sync.Mutex
		results  []*events.Alert
	)
	collect := func(alerts []*events.Alert) {
		if len(alerts) == 0 {
			return
		}
		resultMu.Lock()
		results = append(results, alerts...)
		resultMu.Unlock()
	}

	var wg sync.WaitGroup

	// Layer 1: IOC — hash, IP, domain lookups.
	if e.ioc != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer e.recoverLayer("ioc")
			matches := e.ioc.CheckEvent(event)
			alerts := make([]*events.Alert, 0, len(matches))
			for _, m := range matches {
				alerts = append(alerts, iocMatchToAlert(m, event))
			}
			collect(alerts)
		}()
	}

	// Layer 2: YARA — file scanning (file events only).
	if e.yara != nil && isFileEvent(event) {
		if path := extractFilePath(event); path != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer e.recoverLayer("yara")
				yaraMatches, err := e.yara.ScanFile(ctx, path)
				if err != nil {
					e.logger.Debug("engine: yara scan failed",
						zap.String("path", path), zap.Error(err))
					return
				}
				alerts := make([]*events.Alert, 0, len(yaraMatches))
				for _, ym := range yaraMatches {
					alerts = append(alerts, yaraMatchToAlert(ym, event))
				}
				collect(alerts)
			}()
		}
	}

	// Layer 3: Sigma + Custom CEL rules.
	if e.sigma != nil || e.custom != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer e.recoverLayer("rules")
			m := rules.EventToMap(event)
			if m == nil {
				return
			}
			if e.sigma != nil {
				collect(e.sigma.Evaluate(m))
			}
			if e.custom != nil {
				collect(e.custom.Evaluate(m))
			}
		}()
	}

	// Layer 4: Behavioral detectors + correlator + sequencer.
	if e.correlator != nil {
		e.correlator.AddEvent(event)

		for _, det := range e.behavioral {
			det := det
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer e.recoverLayer(det.Name())
				collect(det.Analyze(event, e.correlator))
			}()
		}

		if e.sequencer != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer e.recoverLayer("sequencer")
				collect(e.sequencer.Analyze(event, e.correlator))
			}()
		}
	}

	// Layer 5: ML model scoring.
	if e.ml != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer e.recoverLayer("ml")
			collect(e.scoreWithML(ctx, event))
		}()
	}

	wg.Wait()

	alerts := deduplicateAlerts(results)
	if merged := mergeScores(alerts); merged != nil {
		alerts = append(alerts, merged)
	}

	// Publish to consumer channel under RLock so Stop cannot close the
	// channel while we are sending.
	e.mu.RLock()
	if e.running {
		for _, a := range alerts {
			select {
			case e.alertCh <- a:
			default:
				e.logger.Warn("engine: alert channel full, dropping alert",
					zap.String("rule_id", a.RuleID))
			}
		}
	}
	e.mu.RUnlock()

	// Layer 6: LLM deep analysis (async, non-blocking).
	if e.llm != nil && e.cfg.LLMEnabled && shouldEscalateToLLM(alerts) {
		e.escalateToLLM(event)
	}

	return alerts
}

// SetLLMEngine attaches an LLM engine for layer 6 deep analysis. It may be
// called after construction to defer LLM provider setup.
func (e *Engine) SetLLMEngine(le *llm.Engine) {
	e.mu.Lock()
	e.llm = le
	e.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Layer helpers
// ---------------------------------------------------------------------------

func (e *Engine) recoverLayer(name string) {
	if r := recover(); r != nil {
		e.logger.Error("engine: layer panicked",
			zap.String("layer", name),
			zap.Any("recover", r))
	}
}

func (e *Engine) scoreWithML(ctx context.Context, event interface{}) []*events.Alert {
	var alerts []*events.Alert

	switch event.(type) {
	case *schema.FileEvent, schema.FileEvent:
		path := extractFilePath(event)
		if path == "" {
			return nil
		}
		score, err := e.ml.ScoreFile(ctx, path)
		if err != nil {
			e.logger.Debug("engine: ml file scoring failed", zap.Error(err))
			return nil
		}
		if score.Malicious {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-pe-classifier",
				RuleName:    "ML PE Classifier",
				Severity:    mlScoreToSeverity(score.Score),
				Title:       fmt.Sprintf("ML: malicious file detected (%.2f)", score.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", score.Category, score.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", score.Category},
				RawEvent:    event,
			})
		}

	case *schema.NetworkEvent, schema.NetworkEvent:
		score, err := e.ml.ScoreNetwork(ctx, event)
		if err != nil {
			e.logger.Debug("engine: ml network scoring failed", zap.Error(err))
			return nil
		}
		if score.Score >= 0.7 {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-network-anomaly",
				RuleName:    "ML Network Anomaly",
				Severity:    mlScoreToSeverity(score.Score),
				Title:       fmt.Sprintf("ML: anomalous network activity (%.2f)", score.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", score.Category, score.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", score.Category},
				RawEvent:    event,
			})
		}

	case *schema.ProcessEvent, schema.ProcessEvent:
		if e.correlator == nil {
			return nil
		}
		pid := extractPID(event)
		window := e.correlator.GetProcessEvents(pid, Window5m)
		if len(window) == 0 {
			return nil
		}
		score, err := e.ml.ScoreProcess(ctx, window)
		if err != nil {
			e.logger.Debug("engine: ml behavior scoring failed", zap.Error(err))
			return nil
		}
		if score.Score >= 0.7 {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-behavior-lstm",
				RuleName:    "ML Behavioral LSTM",
				Severity:    mlScoreToSeverity(score.Score),
				Title:       fmt.Sprintf("ML: suspicious process behavior (%.2f)", score.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", score.Category, score.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", score.Category},
				RawEvent:    event,
			})
		}
	}

	return alerts
}

func (e *Engine) escalateToLLM(event interface{}) {
	pid := extractPID(event)
	eventCtx := &llm.EventContext{Event: event}
	if e.correlator != nil {
		eventCtx.RecentFiles = e.correlator.GetRecentFiles(pid, Window5m)
		eventCtx.RecentConnections = e.correlator.GetRecentConnections(pid, Window5m)
	}

	ch := e.llm.AnalyzeAsync(eventCtx)
	e.llmWg.Add(1)
	go func() {
		defer e.llmWg.Done()
		var res *llm.AnalysisResult
		select {
		case res = <-ch:
		case <-e.stopCh:
			return
		}
		if res.Err != nil {
			e.logger.Warn("engine: llm analysis failed", zap.Error(res.Err))
			return
		}
		if res.Verdict == nil || !res.Verdict.ThreatDetected {
			if res.Verdict != nil {
				e.logger.Info("engine: llm verdict benign",
					zap.String("action", res.Verdict.RecommendedAction),
					zap.Float64("confidence", res.Verdict.Confidence),
					zap.String("fp_risk", res.Verdict.FalsePositiveRisk))
			}
			return
		}
		alert := &events.Alert{
			ID:          uuid.New().String(),
			RuleID:      "llm-deep-analysis",
			RuleName:    "LLM Deep Analysis",
			Severity:    events.Severity(res.Verdict.Severity),
			Title:       fmt.Sprintf("LLM: %s detected", res.Verdict.ThreatType),
			Description: res.Verdict.Reasoning,
			Timestamp:   time.Now().UTC(),
			Tags:        []string{"llm", res.Verdict.ThreatType},
			RawEvent:    event,
		}
		select {
		case e.alertCh <- alert:
		case <-e.stopCh:
		}
	}()
}

// ---------------------------------------------------------------------------
// Alert post-processing
// ---------------------------------------------------------------------------

// deduplicateAlerts removes duplicate alerts sharing the same RuleID within
// a single evaluation pass. The first occurrence wins.
func deduplicateAlerts(alerts []*events.Alert) []*events.Alert {
	if len(alerts) <= 1 {
		return alerts
	}
	seen := make(map[string]struct{}, len(alerts))
	out := make([]*events.Alert, 0, len(alerts))
	for _, a := range alerts {
		if _, dup := seen[a.RuleID]; dup {
			continue
		}
		seen[a.RuleID] = struct{}{}
		out = append(out, a)
	}
	return out
}

// mergeScores creates a composite alert when multiple detection layers fired
// for the same event. The composite inherits the highest severity and
// aggregates MITRE references and tags from all contributing alerts. Returns
// nil when fewer than two alerts are provided.
func mergeScores(alerts []*events.Alert) *events.Alert {
	if len(alerts) < 2 {
		return nil
	}

	highest := alerts[0].Severity
	var allMITRE []events.MITREAttack
	tagSet := make(map[string]struct{})
	ruleNames := make([]string, 0, len(alerts))

	for _, a := range alerts {
		if severityRank(a.Severity) > severityRank(highest) {
			highest = a.Severity
		}
		allMITRE = append(allMITRE, a.MITRE...)
		for _, t := range a.Tags {
			tagSet[t] = struct{}{}
		}
		ruleNames = append(ruleNames, a.RuleName)
	}

	tags := make([]string, 0, len(tagSet)+1)
	for t := range tagSet {
		tags = append(tags, t)
	}
	tags = append(tags, "composite")

	return &events.Alert{
		ID:          uuid.New().String(),
		RuleID:      "composite-detection",
		RuleName:    "Multi-Layer Detection",
		Severity:    highest,
		Title:       fmt.Sprintf("Composite: %d detection layers triggered", len(alerts)),
		Description: fmt.Sprintf("Corroborating detections: %v", ruleNames),
		Timestamp:   time.Now().UTC(),
		MITRE:       deduplicateMITRE(allMITRE),
		Tags:        tags,
		RawEvent:    alerts[0].RawEvent,
	}
}

// shouldEscalateToLLM returns true if any alert has medium severity or above.
func shouldEscalateToLLM(alerts []*events.Alert) bool {
	for _, a := range alerts {
		if severityRank(a.Severity) >= severityRank(events.SeverityMedium) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Alert constructors
// ---------------------------------------------------------------------------

func iocMatchToAlert(m *ioc.MatchResult, raw interface{}) *events.Alert {
	return &events.Alert{
		ID:          uuid.New().String(),
		RuleID:      fmt.Sprintf("ioc-%s-%s", m.Type, m.Indicator),
		RuleName:    fmt.Sprintf("IOC Match: %s", m.Indicator),
		Severity:    events.Severity(m.Severity),
		Title:       fmt.Sprintf("IOC %s match: %s", m.Type, m.Indicator),
		Description: fmt.Sprintf("Matched known malicious %s from %s", m.Type, m.Source),
		Timestamp:   time.Now().UTC(),
		Tags:        m.Tags,
		RawEvent:    raw,
	}
}

func yaraMatchToAlert(m rules.YARAMatch, raw interface{}) *events.Alert {
	sev := events.SeverityHigh
	if s, ok := m.Meta["severity"]; ok {
		sev = events.Severity(fmt.Sprint(s))
	}
	return &events.Alert{
		ID:          uuid.New().String(),
		RuleID:      fmt.Sprintf("yara-%s", m.Rule),
		RuleName:    m.Rule,
		Severity:    sev,
		Title:       fmt.Sprintf("YARA match: %s", m.Rule),
		Description: fmt.Sprintf("File matched YARA rule %s with %d string hits", m.Rule, len(m.Strings)),
		Timestamp:   time.Now().UTC(),
		Tags:        m.Tags,
		RawEvent:    raw,
	}
}

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

func isFileEvent(event interface{}) bool {
	switch event.(type) {
	case *schema.FileEvent, schema.FileEvent:
		return true
	}
	return false
}

func severityRank(s events.Severity) int {
	switch s {
	case events.SeverityCritical:
		return 4
	case events.SeverityHigh:
		return 3
	case events.SeverityMedium:
		return 2
	case events.SeverityLow:
		return 1
	default:
		return 0
	}
}

func mlScoreToSeverity(score float64) events.Severity {
	switch {
	case score >= 0.9:
		return events.SeverityCritical
	case score >= 0.7:
		return events.SeverityHigh
	case score >= 0.5:
		return events.SeverityMedium
	default:
		return events.SeverityLow
	}
}

func deduplicateMITRE(attacks []events.MITREAttack) []events.MITREAttack {
	if len(attacks) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(attacks))
	out := make([]events.MITREAttack, 0, len(attacks))
	for _, a := range attacks {
		if _, dup := seen[a.TechniqueID]; dup {
			continue
		}
		seen[a.TechniqueID] = struct{}{}
		out = append(out, a)
	}
	return out
}
