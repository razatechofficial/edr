package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/ioc"
	"github.com/razatechofficial/edr/internal/detection/llm"
	"github.com/razatechofficial/edr/internal/detection/llm/rag"
	"github.com/razatechofficial/edr/internal/detection/ml"
	"github.com/razatechofficial/edr/internal/detection/rules"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
)

// EngineConfig controls which detection layers are active and where their
// data files reside.
type EngineConfig struct {
	IOCEnabled              bool
	SigmaEnabled            bool
	YARAEnabled             bool
	BehavioralEnabled       bool
	MLEnabled               bool
	LLMEnabled              bool
	WorkerCount             int
	PerformanceProfile      string
	YARAMaxFileSizeMB       int
	YARARescanCooldownSec   int
	YARAMaxScansPerMinute   int
	YARAExcludePathPrefixes []string

	SigmaRulesDir        string
	YARARulesDir         string
	BehavioralChainsPath string
	CustomRulesPath      string
	IOCHashDBPath        string
	IOCIPDBPath          string
	IOCDomainDBPath      string
	MLModelsDir          string

	// ML model filenames (basename only, resolved under MLModelsDir).
	// Empty strings fall back to built-in defaults in ml.NewEngine.
	MLModelPEClassifier        string
	MLModelBehaviorLSTM        string
	MLModelNetworkAnomaly      string
	MLModelNetworkLGBM         string
	MLModelRansomware          string
	MLModelRATC2               string
	MLModelBehaviorTransformer string
	MLModelLOLBin              string
	MLModelSupplyChain         string
	MLModelAIGen               string
	MLModelIdentity            string
	MLModelMemoryInjection     string

	// ML detection thresholds (0.0–1.0). Zero values fall back to defaults.
	MLThresholdPE                float64
	MLThresholdNetwork           float64
	MLThresholdBehavior          float64
	MLThresholdRansomware        float64
	MLThresholdLOLBin            float64
	MLThresholdSupplyChain       float64
	MLThresholdAIGen             float64
	MLThresholdIdentity          float64
	MLThresholdMemoryInjection   float64
	MLThresholdNetworkLGBM       float64
	MLThresholdBehaviorTransformer float64

	// ONNX Runtime settings.
	MLONNXNumThreads  int
	MLONNXUseGPU      bool
	MLONNXGPUDeviceID int

	// LayerTimeout is the maximum duration each detection layer is allowed
	// before its result is discarded. Default: 50ms. ML layer uses MLLayerTimeout.
	LayerTimeout   time.Duration
	// MLLayerTimeout is the extended timeout for ML inference. Default: 150ms.
	MLLayerTimeout time.Duration

	// Hex-encoded Ed25519 public key for verifying ML model signatures.
	// Empty disables signature verification.
	MLVerifyPubKey string

	RAGEnabled        bool
	RAGStoragePath    string
	RAGEmbeddingModel string
	RAGTopK           int
	RAGChunkSize      int
	RAGKnowledgeBases []string

	// DataDir is the agent data directory (dedup_state.json, etc.). Empty disables on-disk dedup state.
	DataDir string
}

// Engine is the main detection orchestrator that runs events through all
// detection layers concurrently and merges results. Layers that fail to
// initialize or panic at runtime are isolated so the remaining layers
// continue to operate.
type Engine struct {
	ioc         *ioc.Matcher
	sigma       *rules.SigmaEngine
	yara        *rules.YARAEngine
	custom      *rules.CustomEngine
	behavioral  []Detector
	correlator  *Correlator
	sequencer   *SequenceEngine
	ml          *ml.Engine
	llm         *llm.Engine
	ragEngine   *rag.Engine
	chain       *BehavioralEngine
	scorer      *ScoringEngine
	fusion      *ScoreFusionEngine
	deduper     *AlertDeduper
	rateLimiter *RuleRateLimiter
	yaraAsyncCh chan rules.YARAScanResult

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

	eventsProcessed   atomic.Uint64
	detectionsEmitted atomic.Uint64
	droppedEvents     atomic.Uint64
	lastLatencyNanos  atomic.Int64
}

// NewEngine creates and initializes all detection layers. Layers whose
// configuration is disabled or whose initialization fails are logged and
// skipped so the remaining layers continue to operate.
func NewEngine(cfg EngineConfig, logger *zap.Logger) (*Engine, error) {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 4
	}
	setRuntimeProfile(cfg.PerformanceProfile)
	alertBuffer := cfg.WorkerCount * 64
	ratePerMin := 30
	rateBurst := 10
	if isLowResourceProfile() {
		alertBuffer = cfg.WorkerCount * 32
		ratePerMin = 12
		rateBurst = 4
	} else if isStrictProfile() {
		alertBuffer = cfg.WorkerCount * 128
		ratePerMin = 120
		rateBurst = 40
	}

	e := &Engine{
		cfg:         cfg,
		workerCount: cfg.WorkerCount,
		alertCh:     make(chan *events.Alert, alertBuffer),
		logger:      logger,
		stopCh:      make(chan struct{}),
		scorer:      NewScoringEngine(),
		fusion:      NewScoreFusionEngine(DefaultScoreFusionConfig()),
		deduper:     NewAlertDeduper(5*time.Minute, cfg.DataDir),
		rateLimiter: NewRuleRateLimiter(ratePerMin, rateBurst, 4096),
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
		yaraMaxFileMB := cfg.YARAMaxFileSizeMB
		if yaraMaxFileMB <= 0 {
			yaraMaxFileMB = 8
		}
		ye, err := rules.NewYARAEngine(cfg.YARARulesDir, yaraMaxFileMB, cfg.WorkerCount, logger, rules.YARAEngineOptions{
			RescanCooldown:  time.Duration(cfg.YARARescanCooldownSec) * time.Second,
			MaxScansPerMin:  cfg.YARAMaxScansPerMinute,
			ExcludePrefixes: cfg.YARAExcludePathPrefixes,
		})
		if err != nil {
			logger.Warn("engine: yara layer init failed, disabling", zap.Error(err))
		} else {
			e.yara = ye
			asyncBuf := 256
			if isLowResourceProfile() {
				asyncBuf = 64
			} else if isStrictProfile() {
				asyncBuf = 512
			}
			e.yaraAsyncCh = make(chan rules.YARAScanResult, asyncBuf)
			ye.SetAsyncSink(e.yaraAsyncCh)
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
			NewRootkitDetector(logger),
			NewPrivacyDetector(logger),
		}
		chainPath := cfg.BehavioralChainsPath
		if strings.TrimSpace(chainPath) == "" {
			chainPath = filepath.Join("rules", "behavioral", "chains.yml")
		}
		if ch, err := NewBehavioralEngine(chainPath, logger); err == nil {
			e.chain = ch
		} else {
			logger.Warn("engine: behavioral chain init failed", zap.Error(err))
		}
	}

	if cfg.MLEnabled && cfg.MLModelsDir != "" {
		// ONNX sessions are created while loading models in ml.NewEngine; runtime must be initialized first.
		if err := ml.InitRuntime(cfg.MLONNXNumThreads, cfg.MLONNXUseGPU, cfg.MLONNXGPUDeviceID); err != nil {
			logONNXInitFailure(logger, err)
		} else {
			peThr := cfg.MLThresholdPE
			if peThr <= 0 || peThr > 1 {
				peThr = 0.80
			}
			me, err := ml.NewEngine(ml.Config{
				ModelsDir:                cfg.MLModelsDir,
				PEClassifierFile:         cfg.MLModelPEClassifier,
				BehaviorLSTMFile:         cfg.MLModelBehaviorLSTM,
				NetworkAnomalyFile:       cfg.MLModelNetworkAnomaly,
				NetworkLGBMFile:         cfg.MLModelNetworkLGBM,
				RansomwareFile:           cfg.MLModelRansomware,
				RATC2File:               cfg.MLModelRATC2,
				BehaviorTransformerFile:  cfg.MLModelBehaviorTransformer,
				LOLBinFile:              cfg.MLModelLOLBin,
				SupplyChainFile:          cfg.MLModelSupplyChain,
				AIGenFile:               cfg.MLModelAIGen,
				IdentityFile:            cfg.MLModelIdentity,
				MemoryInjectionFile:     cfg.MLModelMemoryInjection,
				VerifyPubKeyHex:          cfg.MLVerifyPubKey,
				PEMaliciousThreshold:     peThr,
			}, logger)
			if err != nil {
				logger.Warn("engine: ml layer init failed, disabling", zap.Error(err))
			} else {
				e.ml = me
			}
		}
	}

	if cfg.RAGEnabled && cfg.RAGStoragePath != "" {
		if err := e.initRAG(cfg); err != nil {
			logger.Warn("engine: rag layer init failed, disabling", zap.Error(err))
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

	if e.ml != nil {
		if err := ml.InitRuntime(e.cfg.MLONNXNumThreads, e.cfg.MLONNXUseGPU, e.cfg.MLONNXGPUDeviceID); err != nil {
			logONNXInitFailure(e.logger, err)
		}
	}

	if e.deduper != nil {
		e.deduper.Start()
	}
	if e.chain != nil {
		e.chain.Start(ctx)
	}
	if e.yara != nil && e.yaraAsyncCh != nil {
		e.wg.Add(1)
		go e.yaraResultPump(ctx)
	}

	if e.sigma != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.sigma.WatchAndReload(ctx); err != nil && ctx.Err() == nil {
				e.logger.Error("engine: sigma watcher failed", zap.Error(err))
			}
		}()
	}

	e.logger.Debug("engine: started",
		zap.Bool("ioc", e.ioc != nil),
		zap.Bool("yara", e.yara != nil),
		zap.Bool("sigma", e.sigma != nil),
		zap.Bool("custom", e.custom != nil),
		zap.Int("behavioral_detectors", len(e.behavioral)),
		zap.Bool("sequencer", e.sequencer != nil),
		zap.Bool("ml", e.ml != nil),
		zap.Bool("llm", e.llm != nil),
		zap.Bool("rag", e.ragEngine != nil),
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
	waitWithTimeout := func(wg *sync.WaitGroup, timeout time.Duration) bool {
		done := make(chan struct{})
		go func() {
			defer close(done)
			wg.Wait()
		}()
		select {
		case <-done:
			return true
		case <-time.After(timeout):
			return false
		}
	}
	if !waitWithTimeout(&e.wg, 8*time.Second) {
		e.logger.Warn("engine: timeout waiting for workers during stop")
	}
	if !waitWithTimeout(&e.llmWg, 5*time.Second) {
		e.logger.Warn("engine: timeout waiting for llm workers during stop")
	}
	if e.deduper != nil {
		e.deduper.Stop()
	}
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
	if e.ml != nil {
		record(ml.ShutdownRuntime())
	}
	if e.ragEngine != nil {
		record(e.ragEngine.Close())
	}
	return firstErr
}

// Alerts returns a read-only channel that consumers use to receive detection
// alerts produced by all layers, including asynchronous LLM verdicts.
func (e *Engine) Alerts() <-chan *events.Alert {
	return e.alertCh
}

// Evaluate runs the event through all enabled detection layers concurrently
// with timeout-bounded fan-out and returns the fused, deduplicated set of alerts.
//
// Layer execution (1-5 concurrent with timeout, 6 async fire-and-forget):
//   - Layer 1 (IOC): hash, IP, domain lookups (<1ms target)
//   - Layer 2 (YARA): file scanning for file events (<5ms target)
//   - Layer 3 (Sigma + Custom CEL): rule evaluation (<2ms target)
//   - Layer 4 (Behavioral): 8 detectors + correlator + sequencer (<10ms target)
//   - Layer 5 (ML): model inference when applicable (<15ms target, extended timeout)
//   - Layer 6 (LLM): async deep analysis if layers 1-5 produced medium+ severity
func (e *Engine) Evaluate(ctx context.Context, event interface{}) []*events.Alert {
	start := time.Now()
	e.mu.RLock()
	if !e.running {
		e.mu.RUnlock()
		return nil
	}
	e.mu.RUnlock()
	e.eventsProcessed.Add(1)

	layerTimeout := e.cfg.LayerTimeout
	if layerTimeout <= 0 {
		layerTimeout = 50 * time.Millisecond
	}
	mlTimeout := e.cfg.MLLayerTimeout
	if mlTimeout <= 0 {
		mlTimeout = 150 * time.Millisecond
	}

	layerCtx, layerCancel := context.WithTimeout(ctx, layerTimeout)
	defer layerCancel()

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

	// collectWithTimeout wraps a layer function, discarding results if the
	// context deadline is exceeded.
	collectWithTimeout := func(lctx context.Context, layerName string, fn func() []*events.Alert) {
		done := make(chan []*events.Alert, 1)
		go func() {
			defer e.recoverLayer(layerName)
			done <- fn()
		}()
		select {
		case res := <-done:
			collect(res)
		case <-lctx.Done():
			e.logger.Debug("engine: layer timeout exceeded", zap.String("layer", layerName))
		}
	}

	var wg sync.WaitGroup

	// Layer 1: IOC — hash, IP, domain lookups.
	if e.ioc != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectWithTimeout(layerCtx, "ioc", func() []*events.Alert {
				matches := e.ioc.CheckEvent(event)
				alerts := make([]*events.Alert, 0, len(matches))
				for _, m := range matches {
					alerts = append(alerts, iocMatchToAlert(m, event))
				}
				return alerts
			})
		}()
	}

	// Layer 2: YARA — async file scan (non-blocking; results via yaraResultPump -> alertCh).
	if e.yara != nil && isFileEvent(event) {
		if path := extractFilePath(event); path != "" {
			if !e.yara.EnqueueFileScan(path, event) {
				e.logger.Debug("engine: yara async queue full or sink unset", zap.String("path", path))
			}
		}
	}

	// Layer 3: Sigma + Custom CEL rules.
	if e.sigma != nil || e.custom != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectWithTimeout(layerCtx, "rules", func() []*events.Alert {
				m := rules.EventToMap(event)
				if m == nil {
					return nil
				}
				var out []*events.Alert
				if e.sigma != nil {
					out = append(out, e.sigma.Evaluate(m)...)
				}
				if e.custom != nil {
					out = append(out, e.custom.Evaluate(m)...)
				}
				return out
			})
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
				collectWithTimeout(layerCtx, det.Name(), func() []*events.Alert {
					return det.Analyze(event, e.correlator)
				})
			}()
		}

		if e.sequencer != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				collectWithTimeout(layerCtx, "sequencer", func() []*events.Alert {
					return e.sequencer.Analyze(event, e.correlator)
				})
			}()
		}
	}
	if e.chain != nil {
		for _, d := range e.chain.Process(event) {
			collect([]*events.Alert{detectionToAlert(d)})
		}
	}

	// Wait for layers 1-4 so ML (layer 5) can use prior behavioral alerts.
	wg.Wait()

	// Snapshot prior alerts for ML ransomware correlation.
	resultMu.Lock()
	priorAlerts := make([]*events.Alert, len(results))
	copy(priorAlerts, results)
	resultMu.Unlock()

	// Layer 5: ML model scoring (extended timeout).
	if e.ml != nil {
		mlCtx, mlCancel := context.WithTimeout(ctx, mlTimeout)
		collectWithTimeout(mlCtx, "ml", func() []*events.Alert {
			return e.scoreWithML(mlCtx, event, priorAlerts)
		})
		mlCancel()
	}

	alerts := results
	if e.fusion != nil {
		alerts = e.fusion.Fuse(alerts)
	}
	alerts = e.postProcessAlerts(alerts)

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
				e.droppedEvents.Add(1)
			}
		}
	}
	e.mu.RUnlock()

	// Layer 6: LLM deep analysis (async, non-blocking).
	if e.llm != nil && e.cfg.LLMEnabled && shouldEscalateToLLM(alerts) {
		e.escalateToLLM(event, alerts)
	}
	e.detectionsEmitted.Add(uint64(len(alerts)))
	e.lastLatencyNanos.Store(time.Since(start).Nanoseconds())

	return alerts
}

// Process implements DetectionEngineAPI without disrupting existing Evaluate users.
func (e *Engine) Process(ctx context.Context, event interface{}) []Detection {
	alerts := e.Evaluate(ctx, event)
	out := make([]Detection, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, alertToDetection(a))
	}
	return out
}

// Reload hot-reloads all rule-backed engines.
func (e *Engine) Reload() error {
	if e.ioc != nil && e.cfg.IOCEnabled {
		if err := e.ioc.LoadAll(e.cfg.IOCHashDBPath, e.cfg.IOCIPDBPath, e.cfg.IOCDomainDBPath); err != nil {
			return fmt.Errorf("reload ioc: %w", err)
		}
	}
	if e.sigma != nil {
		if err := e.sigma.LoadRules(); err != nil {
			return err
		}
	}
	if e.yara != nil {
		if err := e.yara.LoadRules(); err != nil {
			return err
		}
	}
	return nil
}

// Stats returns high-level runtime counters for monitoring.
func (e *Engine) Stats() EngineStats {
	rc := RuleCount{}
	if e.sigma != nil {
		rc.Sigma = e.sigma.Count()
	}
	if e.yara != nil {
		rc.YARA = e.yara.Count()
	}
	if e.sequencer != nil {
		rc.Behavioral = len(e.behavioral)
	}
	return EngineStats{
		EventsProcessed:   e.eventsProcessed.Load(),
		DetectionsEmitted: e.detectionsEmitted.Load(),
		RulesLoaded:       rc,
		ProcessingLatency: time.Duration(e.lastLatencyNanos.Load()),
		DroppedEvents:     e.droppedEvents.Load(),
	}
}

// IOCMatcher returns the IOC matcher used by layer 1, or nil if IOC
// detection was not enabled.
func (e *Engine) IOCMatcher() *ioc.Matcher {
	return e.ioc
}

// EnsureIOCMatcher returns the existing IOC matcher or lazily creates one
// so that threat intel feeds can populate it even when the static IOC
// databases were not configured at startup.
func (e *Engine) EnsureIOCMatcher() *ioc.Matcher {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ioc == nil {
		e.ioc = ioc.NewMatcher(e.logger)
	}
	return e.ioc
}

// SetLLMEngine attaches an LLM engine for layer 6 deep analysis. It may be
// called after construction to defer LLM provider setup.
func (e *Engine) SetLLMEngine(le *llm.Engine) {
	e.mu.Lock()
	e.llm = le
	e.mu.Unlock()
}

// HotSwapModel atomically replaces a loaded ML model. The caller must supply
// the raw ONNX bytes and the detached Ed25519 signature (verified only when
// a public key was configured). Valid model names: pe_classifier,
// behavior_lstm, network_anomaly, ransomware.
func (e *Engine) HotSwapModel(name string, data []byte, signature []byte) error {
	if e.ml == nil {
		return fmt.Errorf("engine: ml layer is not enabled")
	}
	return e.ml.Models().HotSwap(name, data, signature)
}

// MLEngine returns the underlying ML engine, or nil if ML is disabled.
func (e *Engine) MLEngine() *ml.Engine {
	return e.ml
}

// ---------------------------------------------------------------------------
// Layer helpers
// ---------------------------------------------------------------------------

func (e *Engine) yaraResultPump(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case res, ok := <-e.yaraAsyncCh:
			if !ok {
				return
			}
			e.processYARAScanResult(res)
		}
	}
}

// ScanFileForValidation runs a synchronous YARA scan for validation harnesses.
func (e *Engine) ScanFileForValidation(ctx context.Context, path string) []Detection {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	y := e.yara
	e.mu.RUnlock()
	if y == nil {
		return nil
	}
	matches, err := y.ScanFile(ctx, path)
	if err != nil || len(matches) == 0 {
		return nil
	}
	raw := &schema.FileEvent{Path: path}
	out := make([]Detection, 0, len(matches))
	for _, m := range matches {
		out = append(out, FromAlert(yaraMatchToAlert(m, raw)))
	}
	return out
}

func (e *Engine) processYARAScanResult(res rules.YARAScanResult) {
	for _, ym := range res.Matches {
		if shouldSuppressYARANoise(ym, res.Path) {
			continue
		}
		a := yaraMatchToAlert(ym, res.Event)
		d := alertToDetection(a)
		if e.scorer != nil {
			e.scorer.Score(&d)
		}
		if e.deduper != nil && e.deduper.IsDuplicate(d) {
			continue
		}
		out := detectionToAlert(d)
		out.FilePath = a.FilePath
		out.FileSHA256 = a.FileSHA256
		out.Title = a.Title
		e.mu.RLock()
		running := e.running
		e.mu.RUnlock()
		if !running {
			return
		}
		if e.rateLimiter != nil && !e.rateLimiter.Allow(out.RuleID) {
			e.droppedEvents.Add(1)
			continue
		}
		select {
		case e.alertCh <- out:
			e.detectionsEmitted.Add(1)
		case <-e.stopCh:
			return
		default:
			e.droppedEvents.Add(1)
		}
	}
}

func shouldSuppressYARANoise(m rules.YARAMatch, path string) bool {
	ns := strings.ToLower(strings.TrimSpace(m.Namespace))
	if ns != "documents" {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	// Document macro signatures should not trigger on system libraries/config paths.
	return strings.HasPrefix(p, "/usr/lib/") ||
		strings.HasPrefix(p, "/lib/") ||
		strings.HasPrefix(p, "/lib64/") ||
		strings.HasPrefix(p, "/usr/share/") ||
		strings.HasPrefix(p, "/etc/")
}

// postProcessAlerts scores all alerts, applies AlertDeduper, and prepends
// deduplication window summaries. YARA async path does the same in processYARAScanResult.
func (e *Engine) postProcessAlerts(in []*events.Alert) []*events.Alert {
	var pre []*events.Alert
	if e.deduper != nil {
		for _, d := range e.deduper.DrainExpired() {
			if e.scorer != nil {
				e.scorer.Score(&d)
			}
			pre = append(pre, detectionToAlert(d))
		}
	}
	out := make([]*events.Alert, 0, len(in)+len(pre))
	out = append(out, pre...)
	for _, a := range in {
		d := alertToDetection(a)
		if e.scorer != nil {
			e.scorer.Score(&d)
		}
		if e.deduper != nil && e.deduper.IsDuplicate(d) {
			continue
		}
		a2 := detectionToAlert(d)
		if a.FilePath != "" {
			a2.FilePath = a.FilePath
		}
		if a.FileSHA256 != "" {
			a2.FileSHA256 = a.FileSHA256
		}
		if a.Title != "" {
			a2.Title = a.Title
		}
		if a.Description != "" {
			a2.Description = a.Description
		}
		if len(a.MITRE) > 0 {
			a2.MITRE = a.MITRE
		}
		if len(a.Tags) > 0 {
			a2.Tags = a.Tags
		}
		if e.rateLimiter != nil &&
			!strings.HasPrefix(a2.RuleID, "dedup-") &&
			!e.rateLimiter.Allow(a2.RuleID) {
			e.droppedEvents.Add(1)
			continue
		}
		out = append(out, a2)
	}
	return out
}

func (e *Engine) recoverLayer(name string) {
	if r := recover(); r != nil {
		e.logger.Error("engine: layer panicked",
			zap.String("layer", name),
			zap.Any("recover", r))
	}
}

func (e *Engine) mlThresholdPE() float64 {
	if e.cfg.MLThresholdPE > 0 {
		return e.cfg.MLThresholdPE
	}
	return 0.80
}

func (e *Engine) mlThresholdNetwork() float64 {
	if e.cfg.MLThresholdNetwork > 0 {
		return e.cfg.MLThresholdNetwork
	}
	return 0.70
}

func (e *Engine) mlThresholdBehavior() float64 {
	if e.cfg.MLThresholdBehavior > 0 {
		return e.cfg.MLThresholdBehavior
	}
	return 0.75
}

func (e *Engine) mlThresholdRansomware() float64 {
	if e.cfg.MLThresholdRansomware > 0 {
		return e.cfg.MLThresholdRansomware
	}
	return 0.85
}

func (e *Engine) mlThresholdLOLBin() float64 {
	if e.cfg.MLThresholdLOLBin > 0 {
		return e.cfg.MLThresholdLOLBin
	}
	return 0.75
}

func (e *Engine) mlThresholdSupplyChain() float64 {
	if e.cfg.MLThresholdSupplyChain > 0 {
		return e.cfg.MLThresholdSupplyChain
	}
	return 0.75
}

func (e *Engine) mlThresholdAIGen() float64 {
	if e.cfg.MLThresholdAIGen > 0 {
		return e.cfg.MLThresholdAIGen
	}
	return 0.75
}

func (e *Engine) mlThresholdNetworkLGBM() float64 {
	if e.cfg.MLThresholdNetworkLGBM > 0 {
		return e.cfg.MLThresholdNetworkLGBM
	}
	if e.cfg.MLThresholdNetwork > 0 {
		return e.cfg.MLThresholdNetwork
	}
	return 0.70
}

func (e *Engine) mlThresholdMemoryInjection() float64 {
	if e.cfg.MLThresholdMemoryInjection > 0 {
		return e.cfg.MLThresholdMemoryInjection
	}
	return 0.75
}

func (e *Engine) mlThresholdBehaviorTransformer() float64 {
	if e.cfg.MLThresholdBehaviorTransformer > 0 {
		return e.cfg.MLThresholdBehaviorTransformer
	}
	if e.cfg.MLThresholdBehavior > 0 {
		return e.cfg.MLThresholdBehavior
	}
	return 0.75
}

func (e *Engine) mlThresholdIdentity() float64 {
	if e.cfg.MLThresholdIdentity > 0 {
		return e.cfg.MLThresholdIdentity
	}
	return 0.75
}

func (e *Engine) scoreWithML(ctx context.Context, event interface{}, priorAlerts []*events.Alert) []*events.Alert {
	var alerts []*events.Alert

	switch event.(type) {
	case *schema.FileEvent, schema.FileEvent:
		path := extractFilePath(event)
		if path == "" {
			return nil
		}

		// PE classifier
		if peScore, err := e.ml.ScoreFile(ctx, path); err == nil && peScore.Score >= e.mlThresholdPE() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-pe-classifier",
				RuleName:    "ML PE Classifier",
				Severity:    mlScoreToSeverity(peScore.Score),
				Title:       fmt.Sprintf("ML: malicious file detected (%.2f)", peScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", peScore.Category, peScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", peScore.Category},
				RawEvent:    event,
			})
		}

		// Supply Chain detector
		if scScore, err := e.ml.ScoreSupplyChain(ctx, event); err == nil && scScore.Score >= e.mlThresholdSupplyChain() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-supply-chain",
				RuleName:    "ML Supply Chain Detector",
				Severity:    mlScoreToSeverity(scScore.Score),
				Title:       fmt.Sprintf("ML: supply chain anomaly (%.2f)", scScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", scScore.Category, scScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "supply_chain", scScore.Category},
				RawEvent:    event,
			})
		}

		// AI-Gen detector
		if agScore, err := e.ml.ScoreAIGen(ctx, event); err == nil && agScore.Score >= e.mlThresholdAIGen() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-aigen",
				RuleName:    "ML AI-Generated Malware Detector",
				Severity:    mlScoreToSeverity(agScore.Score),
				Title:       fmt.Sprintf("ML: AI-generated malware indicators (%.2f)", agScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", agScore.Category, agScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "aigen", agScore.Category},
				RawEvent:    event,
			})
		}

	case *schema.NetworkEvent, schema.NetworkEvent:
		score, err := e.ml.ScoreNetworkEnsemble(ctx, event)
		if err != nil {
			e.logger.Debug("engine: ml network scoring failed", zap.Error(err))
			return nil
		}
		if score.Score >= e.mlThresholdNetwork() {
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

		// Dedicated RAT C2 beacon detector
		if c2Score, c2Err := e.ml.ScoreNetworkRATC2(ctx, event); c2Err == nil && c2Score.Score >= e.mlThresholdNetwork() {
			c2RuleID := "ml-rat-c2"
			c2Sev := mlScoreToSeverity(c2Score.Score)
			if score.Score >= e.mlThresholdNetwork() {
				c2Sev = events.SeverityCritical
				c2RuleID = "ml-rat-c2-beacon"
			}
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      c2RuleID,
				RuleName:    "ML RAT C2 Detector",
				Severity:    c2Sev,
				Title:       fmt.Sprintf("ML: RAT C2 beacon pattern (%.2f)", c2Score.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", c2Score.Category, c2Score.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "rat", "c2_beacon", c2Score.Category},
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
		score, err := e.ml.ScoreProcessEnsemble(ctx, window)
		if err != nil {
			// fall back to LSTM-only if ensemble fails
			score, err = e.ml.ScoreProcess(ctx, window)
			if err != nil {
				e.logger.Debug("engine: ml behavior scoring failed", zap.Error(err))
				return nil
			}
		}
		if score.Score >= e.mlThresholdBehavior() {
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

		// LOLBin detector
		if lbScore, err := e.ml.ScoreLOLBin(ctx, event); err == nil && lbScore.Score >= e.mlThresholdLOLBin() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-lolbin",
				RuleName:    "ML LOLBin Detector",
				Severity:    mlScoreToSeverity(lbScore.Score),
				Title:       fmt.Sprintf("ML: LOLBin abuse detected (%.2f)", lbScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", lbScore.Category, lbScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "lolbin", lbScore.Category},
				RawEvent:    event,
			})
		}

	case *schema.AuthEvent, schema.AuthEvent:
		if idScore, err := e.ml.ScoreIdentity(ctx, event); err == nil && idScore.Score >= e.mlThresholdIdentity() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-identity",
				RuleName:    "ML Identity Threat Detector",
				Severity:    mlScoreToSeverity(idScore.Score),
				Title:       fmt.Sprintf("ML: identity threat detected (%.2f)", idScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", idScore.Category, idScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "identity", idScore.Category},
				RawEvent:    event,
			})
		}

	case *schema.MemoryEvent, schema.MemoryEvent:
		if memScore, err := e.ml.ScoreMemoryInjection(ctx, event); err == nil && memScore.Score >= e.mlThresholdMemoryInjection() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-memory-injection",
				RuleName:    "ML Memory Injection Detector",
				Severity:    mlScoreToSeverity(memScore.Score),
				Title:       fmt.Sprintf("ML: memory injection indicators (%.2f)", memScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", memScore.Category, memScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "memory_injection", memScore.Category},
				RawEvent:    event,
			})
		}
	}

	// Score ransomware when prior behavioral alerts contain ransomware signals.
	if ransomIndicators := e.extractRansomwareIndicators(priorAlerts); len(ransomIndicators) > 0 {
		rScore, err := e.ml.ScoreRansomware(ctx, ransomIndicators)
		if err != nil {
			e.logger.Debug("engine: ml ransomware scoring failed", zap.Error(err))
		} else if rScore.Score >= e.mlThresholdRansomware() {
			alerts = append(alerts, &events.Alert{
				ID:          uuid.New().String(),
				RuleID:      "ml-ransomware",
				RuleName:    "ML Ransomware Classifier",
				Severity:    mlScoreToSeverity(rScore.Score),
				Title:       fmt.Sprintf("ML: ransomware activity detected (%.2f)", rScore.Score),
				Description: fmt.Sprintf("Category %s, confidence %.2f", rScore.Category, rScore.Confidence),
				Timestamp:   time.Now().UTC(),
				Tags:        []string{"ml", "ransomware", rScore.Category},
				RawEvent:    event,
			})
		}
	}

	return alerts
}

// extractRansomwareIndicators builds a ransomware indicator map from prior
// behavioral alerts. Returns nil if no ransomware-related alerts are present.
func (e *Engine) extractRansomwareIndicators(priorAlerts []*events.Alert) map[string]float64 {
	var found bool
	for _, a := range priorAlerts {
		for _, t := range a.Tags {
			if t == "ransomware" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nil
	}

	indicators := make(map[string]float64)
	for _, a := range priorAlerts {
		desc := a.Description + " " + a.Title
		if containsIndicator(desc, "entropy") {
			indicators["entropy_increase_rate"] = 0.9
		}
		if containsIndicator(desc, "mass_file") || containsIndicator(desc, "mass file") {
			indicators["file_rename_rate"] = 0.8
			indicators["file_delete_rate"] = 0.7
		}
		if containsIndicator(desc, "extension") {
			indicators["file_type_change_rate"] = 0.9
			indicators["known_extension_append"] = 0.9
		}
		if containsIndicator(desc, "shadow") {
			indicators["shadow_copy_deletion"] = 1.0
		}
		if containsIndicator(desc, "ransom_note") || containsIndicator(desc, "ransom note") {
			indicators["ransom_note_similarity"] = 0.9
		}
		if containsIndicator(desc, "encrypt") {
			indicators["encryption_api_calls"] = 0.8
		}
	}
	return indicators
}

func containsIndicator(text, keyword string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(keyword))
}

func (e *Engine) escalateToLLM(event interface{}, priorAlerts []*events.Alert) {
	pid := extractPID(event)
	eventCtx := &llm.EventContext{Event: event}

	if e.correlator != nil {
		eventCtx.RecentFiles = e.correlator.GetRecentFiles(pid, Window5m)
		eventCtx.RecentConnections = e.correlator.GetRecentConnections(pid, Window5m)

		for _, entry := range e.correlator.GetProcessTree(pid, Window5m) {
			eventCtx.ProcessTree = append(eventCtx.ProcessTree, llm.ProcessInfo{
				PID: entry.PID, PPID: entry.PPID,
				Name: entry.Name, Path: entry.Path,
				Args: entry.Args, User: entry.User,
			})
		}

		eventCtx.RecentRegistryChanges = e.correlator.GetRecentRegistryChanges(pid, Window5m)
	}

	if e.ioc != nil {
		for _, m := range e.ioc.CheckEvent(event) {
			entry := fmt.Sprintf("Known malicious %s: %s (source: %s)", m.Type, m.Indicator, m.Source)
			if m.MalwareFamily != "" {
				entry += fmt.Sprintf(", family: %s", m.MalwareFamily)
			}
			eventCtx.ThreatIntelContext = append(eventCtx.ThreatIntelContext, entry)
		}
	}

	for _, a := range priorAlerts {
		eventCtx.BehavioralIndicators = append(eventCtx.BehavioralIndicators,
			fmt.Sprintf("[%s] %s (severity: %s)", a.RuleName, a.Title, a.Severity))
	}

	if e.ragEngine != nil {
		e.enrichFromRAG(eventCtx)
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

// initRAG creates the RAG engine and indexes the configured knowledge bases.
func (e *Engine) initRAG(cfg EngineConfig) error {
	re, err := rag.NewEngine(cfg.RAGStoragePath, cfg.RAGEmbeddingModel, cfg.RAGTopK, cfg.RAGChunkSize)
	if err != nil {
		return fmt.Errorf("rag init: %w", err)
	}
	ctx := context.Background()
	for _, kb := range cfg.RAGKnowledgeBases {
		if err := re.IndexKnowledgeBase(ctx, kb); err != nil {
			e.logger.Warn("engine: rag knowledge base index failed",
				zap.String("kb", kb), zap.Error(err))
		}
	}
	e.ragEngine = re
	return nil
}

// SetRAGEngine attaches a pre-configured RAG engine. It may be called after
// construction to defer RAG setup or supply an externally created engine.
func (e *Engine) SetRAGEngine(re *rag.Engine) {
	e.mu.Lock()
	e.ragEngine = re
	e.mu.Unlock()
}

// enrichFromRAG queries the RAG engine for knowledge relevant to the event
// and appends results to the EventContext. Failures are logged and silently
// ignored so the LLM analysis proceeds without RAG context.
func (e *Engine) enrichFromRAG(eventCtx *llm.EventContext) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := buildRAGQuery(eventCtx)
	chunks, err := e.ragEngine.Query(ctx, query)
	if err != nil {
		e.logger.Debug("engine: rag query failed, continuing without", zap.Error(err))
		return
	}

	for _, chunk := range chunks {
		if chunk.Score < 0.1 {
			continue
		}
		eventCtx.SimilarHistorical = append(eventCtx.SimilarHistorical, map[string]interface{}{
			"source": chunk.Metadata["source"],
			"text":   chunk.Text,
			"score":  chunk.Score,
		})
	}
}

func buildRAGQuery(eventCtx *llm.EventContext) string {
	var parts []string
	if eventCtx.Event != nil {
		if raw, err := json.Marshal(eventCtx.Event); err == nil {
			parts = append(parts, string(raw))
		}
	}
	for _, ti := range eventCtx.ThreatIntelContext {
		parts = append(parts, ti)
	}
	for _, bi := range eventCtx.BehavioralIndicators {
		parts = append(parts, bi)
	}
	if len(parts) == 0 {
		return "security event analysis"
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// Alert post-processing
// ---------------------------------------------------------------------------

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

	fp := alerts[0].FilePath
	h256 := alerts[0].FileSHA256
	for _, a := range alerts[1:] {
		if fp == "" && a.FilePath != "" {
			fp = a.FilePath
		}
		if h256 == "" && a.FileSHA256 != "" {
			h256 = a.FileSHA256
		}
	}
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
		FilePath:    fp,
		FileSHA256:  h256,
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

// maxYARAHashBytes caps hashing work for very large files (SHA-256 of first N bytes).
const maxYARAHashBytes = 64 << 20

// yaraNamespaceDefault maps rule directory namespace to default detection severity.
var yaraNamespaceDefault = map[string]Severity{
	"malware":   P0,
	"shellcode": P0,
	"exploits":  P1,
	"webshells": P1,
	"lolbins":   P1,
	"packers":   P2,
	"documents": P2,
	"cloud":     P1,
	"linux":     P1,
	"macos":     P1,
}

func yaraMatchSeverity(namespace string, meta map[string]interface{}) Severity {
	if s, ok := meta["severity"]; ok {
		return parseYARASeverityString(fmt.Sprint(s))
	}
	if s, ok := yaraNamespaceDefault[strings.ToLower(strings.TrimSpace(namespace))]; ok {
		return s
	}
	return P2
}

func parseYARASeverityString(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "p0":
		return P0
	case "high", "p1":
		return P1
	case "medium", "p2":
		return P2
	default:
		return P3
	}
}

func yaraMatchToAlert(m rules.YARAMatch, raw interface{}) *events.Alert {
	dsev := yaraMatchSeverity(m.Namespace, m.Meta)
	evsev := pToAlertSeverity(dsev)
	path := extractFilePath(raw)
	desc := fmt.Sprintf("File matched YARA rule %s with %d string hits", m.Rule, len(m.Strings))
	if path != "" {
		desc = fmt.Sprintf("%s; path=%s", desc, path)
	}
	hash := extractFileHashFromEvent(raw)
	if hash == "" && path != "" {
		var partial bool
		var err error
		hash, partial, err = hashFileSHA256Prefix(path, maxYARAHashBytes)
		if err != nil {
			desc = fmt.Sprintf("%s; sha256_error=%v", desc, err)
		} else if hash != "" && partial {
			desc = fmt.Sprintf("%s; file_sha256=%s (first %d bytes of file)", desc, hash, maxYARAHashBytes)
		} else if hash != "" {
			desc = fmt.Sprintf("%s; file_sha256=%s", desc, hash)
		}
	} else if hash != "" {
		desc = fmt.Sprintf("%s; file_sha256=%s", desc, hash)
	}
	return &events.Alert{
		ID:          uuid.New().String(),
		RuleID:      fmt.Sprintf("yara-%s", m.Rule),
		RuleName:    m.Rule,
		Severity:    evsev,
		Title:       fmt.Sprintf("YARA match: %s", m.Rule),
		Description: desc,
		Timestamp:   time.Now().UTC(),
		Tags:        m.Tags,
		RawEvent:    raw,
		FilePath:    path,
		FileSHA256:  hash,
	}
}

func hashFileSHA256Prefix(path string, maxBytes int64) (hashHex string, partial bool, err error) {
	fi, statErr := os.Stat(path)
	if statErr != nil {
		return "", false, statErr
	}
	if !fi.Mode().IsRegular() {
		return "", false, fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBytes)); err != nil {
		return "", false, err
	}
	partial = fi.Size() > maxBytes
	return hex.EncodeToString(h.Sum(nil)), partial, nil
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

// logONNXInitFailure uses Info when the shared library is simply missing (typical dev
// machines); Warn for unexpected init errors.
func logONNXInitFailure(logger *zap.Logger, err error) {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no such file") || strings.Contains(msg, "cannot open shared object file") {
		logger.Info("engine: ONNX Runtime not found; ML layer disabled - install the library or extend DYLD_LIBRARY_PATH / LD_LIBRARY_PATH",
			zap.Error(err))
		return
	}
	logger.Warn("engine: ONNX runtime init failed, ML layer disabled", zap.Error(err))
}
