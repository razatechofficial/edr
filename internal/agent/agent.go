package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/baseline"
	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/comms"
	"github.com/razatechofficial/edr/internal/compliance/sca"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detect"
	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/detection/ioc"
	"github.com/razatechofficial/edr/internal/detection/llm"
	"github.com/razatechofficial/edr/internal/detection/llm/providers"
	mlpkg "github.com/razatechofficial/edr/internal/detection/ml"
	"github.com/razatechofficial/edr/internal/forwarder"
	"github.com/razatechofficial/edr/internal/forensics"
	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/pidfile"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/selfprotect"
	"github.com/razatechofficial/edr/internal/spool"
	"github.com/razatechofficial/edr/internal/telemetry"
	"github.com/razatechofficial/edr/internal/telemetryqueue"
	"github.com/razatechofficial/edr/internal/threatintel"
	"github.com/razatechofficial/edr/internal/xdrclient"
	"github.com/razatechofficial/edr/pkg/events"
)

type Agent struct {
	logger       *slog.Logger
	cfg          config.Config
	collectors   []collector.Collector
	ruleSet      rules.RuleSet
	eventSpool   *spool.Queue[schema.ProcessEvent]
	alertSpool   *spool.Queue[schema.Alert]
	detector     *detect.Engine
	advEngine    *detection.Engine
	llmEngine    *llm.Engine
	threatIntel  *threatintel.Manager
	responder    *response.Responder
	writer       *alert.Writer
	forwarder    forwarder.Forwarder
	forwardDrain forwarder.Drainer
	killAllow    map[string]struct{}
	zapLogger    *zap.Logger

	baselineEngine  *baseline.BaselineEngine
	baselineStorage *baseline.BaselineStorage
	baselineNet     *baseline.NetworkBaseline
	baselineProc    *baseline.ProcessBaseline
	baselineUser    *baseline.UserBaseline

	scaRunner *sca.Runner

	antiDebug     *selfprotect.AntiDebugger
	tamper        *selfprotect.TamperDetector
	integrity     *selfprotect.IntegrityChecker
	respEngine    *response.ActionEngine
	responseLayer response.ResponseEngine

	durableSpool     *telemetry.Spool
	telExporter      *mlpkg.TelemetryExporter
	mlAutoUpdater    *mlpkg.AutoUpdater
	driftDetector    *mlpkg.DriftDetector
	feedbackIngester *mlpkg.FeedbackIngester

	userLookup     *collector.UsernameCache
	fileDedup      *collector.FileDeduper
	fileHashPool   *fileHashPool
	telemetryRelay *forwarder.TelemetryRelay
	// telemetrySealSender mirrors forwarder seal settings for diagnostics (no live transport).
	telemetrySealSender *telemetry.Sender

	xdrIngest *xdrclient.IngestClient
	xdrStore  xdrclient.Store
	xdrState  xdrclient.State

	healthMu           sync.Mutex
	lastHealthSnapshot time.Time
	validationMu       sync.RWMutex
	validationSink     func(detection.Detection)
	noisyAlertMu       sync.Mutex
	noisyAlertLastSeen map[string]time.Time

	controlPlane      *comms.ControlPlane
	controlPlaneQueue *comms.AlertQueue
}

// SetValidationSink registers a callback invoked for each detection surfaced by the agent.
// It is used by cmd/agent --test-mode to verify detections in real time.
func (a *Agent) SetValidationSink(sink func(detection.Detection)) {
	if a == nil {
		return
	}
	a.validationMu.Lock()
	a.validationSink = sink
	a.validationMu.Unlock()
}

func NewDefault() (*Agent, error) {
	return NewWithFiles("configs/agent.example.yaml")
}

func NewWithFiles(configPath string) (*Agent, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	normalizePerformanceProfile(&cfg)
	applyRuntimeLimits(cfg, slog.Default())
	if cfg.ML.Enabled && cfg.ML.RequireRuntime {
		if err := mlpkg.InitRuntime(cfg.ML.ONNX.NumThreads, cfg.ML.ONNX.UseGPU, cfg.ML.ONNX.GPUDeviceID); err != nil {
			return nil, fmt.Errorf("ml.require_runtime: ONNX Runtime init failed: %w", err)
		}
	}
	users := collector.NewUsernameCache()
	cols, err := collector.DefaultCollectors(cfg, users)
	if err != nil {
		return nil, err
	}
	var rs rules.RuleSet
	if cfg.RulesVerifyPubKeyPath != "" {
		rs, err = rules.LoadVerified(cfg.RulesFile, cfg.RulesVerifyPubKeyPath)
	} else {
		rs, err = rules.Load(cfg.RulesFile)
	}
	if err != nil {
		return nil, err
	}

	zapLogger, _ := zap.NewProduction(zap.WithCaller(false))

	a := &Agent{
		logger:             slog.Default(),
		cfg:                cfg,
		collectors:         cols,
		ruleSet:            rs,
		eventSpool:         spool.NewQueueWithLimit[schema.ProcessEvent](cfg.Performance.EventBufferSize),
		alertSpool:         spool.NewQueueWithLimit[schema.Alert](cfg.Performance.EventBufferSize),
		detector:           detect.NewEngine(rs),
		responder:          response.NewResponder(cfg.LegacyResponse.AllowKill, cfg.LegacyResponse.ProtectedProcesses),
		writer:             alert.NewWriter(cfg.Logging.AlertFile, cfg.Logging.AuditFile, 5*1024*1024),
		killAllow:          makeRuleAllowlist(cfg.LegacyResponse.KillRuleAllowlist),
		zapLogger:          zapLogger,
		userLookup:         users,
		fileDedup:          collector.NewFileDeduper(0),
		fileHashPool:       newFileHashPool(),
		noisyAlertLastSeen: make(map[string]time.Time),
	}
	a.writer.SetProductVersion(cfg.Agent.Version)
	collector.LogMonitoringBootstrap(a.logger, cfg)
	collector.SetOCSFProductVersion(cfg.Agent.Version)

	telEP := strings.TrimSpace(cfg.Forwarder.TelemetryEndpoint)
	if telEP == "" {
		telEP = strings.TrimSpace(cfg.Forwarder.Endpoint)
	}
	// Prefer XDR gRPC ingest when configured; otherwise keep HTTP telemetry relay.
	if cfg.XDR.EnabledForEnrollment() {
		if err := a.initXDR(); err != nil {
			return nil, err
		}
	} else if telEP != "" {
		qdir := filepath.Join(cfg.Agent.DataDir, "telemetry-queue")
		qm, qerr := telemetryqueue.NewManager(qdir, 500<<20)
		if qerr != nil {
			a.logger.Warn("telemetry disk queue init failed", "error", qerr)
		} else {
			a.telemetryRelay = forwarder.NewTelemetryRelay(telEP, qm, a.logger)
			sealFn, _, serr := buildTelemetryEnvelopeSealer(cfg)
			if serr != nil {
				a.logger.Error("telemetry sealer init failed", "error", serr, "telemetry_sealer_init_failed", true)
			} else if sealFn != nil {
				a.telemetryRelay.SetSealer(sealFn)
				a.logger.Info("telemetry relay envelope sealing enabled", "key_id", cfg.Forwarder.SealKeyID)
			}
			a.logger.Info("telemetry relay configured", "endpoint", telEP, "queue_dir", qdir)
		}
	}

	if err := a.initAdvancedDetection(); err != nil {
		if a.cfg.ML.Enabled && a.cfg.ML.RequireRuntime {
			return nil, fmt.Errorf("advanced detection engine init failed (ml.require_runtime): %w", err)
		}
		a.logger.Warn("advanced detection engine init failed, using basic rules only", "error", err)
	}

	if err := a.initThreatIntel(); err != nil {
		a.logger.Warn("threat intel init failed", "error", err)
	}

	if err := a.initBaseline(); err != nil {
		a.logger.Warn("baseline engine init failed", "error", err)
	}

	if err := a.initCompliance(); err != nil {
		a.logger.Warn("compliance sca init failed", "error", err)
	}

	spoolDir := filepath.Join(cfg.Agent.DataDir, "alert-spool")
	ds, err := telemetry.NewSpool(spoolDir, zapLogger)
	if err != nil {
		a.logger.Warn("durable spool init failed, alerts not crash-resilient", "error", err)
	} else {
		a.durableSpool = ds
		a.logger.Info("durable alert spool enabled", "path", spoolDir)
	}

	if cfg.Forwarder.SealEnvelopes {
		sealS := telemetry.NewSender(telemetry.NoopTransport{}, nil, telemetry.DefaultSenderConfig(), zapLogger)
		if err := applyEnvelopeSealerToSender(sealS, cfg); err != nil {
			a.logger.Warn("telemetry.Sender envelope sealer unavailable", "error", err)
		}
		a.telemetrySealSender = sealS
	}

	if err := a.initSelfProtect(); err != nil {
		a.logger.Warn("self-protection init failed", "error", err)
	}

	if err := a.initResponseEngine(); err != nil {
		a.logger.Warn("response engine init failed, using basic responder only", "error", err)
	}
	if err := a.initResponseLayer(); err != nil {
		a.logger.Warn("response playbook layer init failed", "error", err)
	}

	if err := a.initControlPlane(); err != nil {
		a.logger.Warn("control plane init failed", "error", err)
	}

	if cfg.ML.Enabled && cfg.ML.ModelsDir != "" {
		exportDir := filepath.Join(cfg.Agent.DataDir, "telemetry-export")
		a.telExporter = mlpkg.NewTelemetryExporter(exportDir, 10000)
		a.logger.Info("telemetry exporter enabled", "dir", exportDir)

		a.driftDetector = mlpkg.NewDriftDetector(1000, 2.0)
		a.logger.Info("drift detector enabled")

		feedbackDir := filepath.Join(cfg.Agent.DataDir, "feedback")
		a.feedbackIngester = mlpkg.NewFeedbackIngester(feedbackDir, a.telExporter, a.zapLogger)
		a.logger.Info("analyst feedback ingester configured", "dir", feedbackDir)

		if cfg.ML.AutoUpdate {
			eng := a.advEngine.MLEngine()
			if eng != nil {
				a.mlAutoUpdater = mlpkg.NewAutoUpdater(eng, cfg.ML.ModelsDir, cfg.ML.UpdateIntervalH, a.zapLogger)
				a.logger.Info("ml auto-updater configured", "interval_hours", cfg.ML.UpdateIntervalH)
			}
		}
	}

	if cfg.Forwarder.Enabled {
		fw, dr, err := forwarder.New(forwarder.Config{
			Mode:           cfg.Forwarder.Mode,
			HTTPEndpoint:   cfg.Forwarder.Endpoint,
			SyslogAddr:     cfg.Forwarder.SyslogAddr,
			KafkaBrokers:   cfg.Forwarder.KafkaBrokers,
			KafkaTopic:     cfg.Forwarder.KafkaTopic,
			RetryMax:       cfg.Forwarder.RetryMax,
			SpoolPath:      cfg.Forwarder.SpoolPath,
			SealEnvelopes:  cfg.Forwarder.SealEnvelopes,
			SealKeyPath:    cfg.Forwarder.SealKeyPath,
			SealKeyID:      cfg.Forwarder.SealKeyID,
		}, a.logger)
		if err != nil {
			return nil, err
		}
		a.forwarder = fw
		a.forwardDrain = dr
	}
	return a, nil
}

func (a *Agent) initAdvancedDetection() error {
	var customRulesPath string
	if a.cfg.Detection.CustomRules.Enabled {
		customRulesPath = a.cfg.Detection.CustomRules.RulesPath
	}
	dataDir := a.cfg.Agent.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/edr"
	}
	behavioralChainsPath := filepath.Join("rules", "behavioral", "chains.yml")
	if sdir := strings.TrimSpace(a.cfg.Detection.Sigma.RulesDir); sdir != "" {
		behavioralChainsPath = filepath.Join(filepath.Dir(sdir), "behavioral", "chains.yml")
	} else if rf := strings.TrimSpace(a.cfg.RulesFile); rf != "" {
		behavioralChainsPath = filepath.Join(filepath.Dir(rf), "behavioral", "chains.yml")
	}
	ecfg := detection.EngineConfig{
		BehavioralEnabled:       true,
		SigmaEnabled:            a.cfg.Detection.Sigma.Enabled,
		DataDir:                 dataDir,
		YARAEnabled:             a.cfg.Detection.YARA.Enabled,
		IOCEnabled:              a.cfg.Detection.IOC.Enabled,
		MLEnabled:               a.cfg.ML.Enabled,
		LLMEnabled:              a.cfg.LLM.Enabled,
		SigmaRulesDir:           a.cfg.Detection.Sigma.RulesDir,
		YARARulesDir:            a.cfg.Detection.YARA.RulesDir,
		YARAMaxFileSizeMB:       a.cfg.Detection.YARA.MaxFileSizeMB,
		YARARescanCooldownSec:   a.cfg.Detection.YARA.RescanCooldownSec,
		YARAMaxScansPerMinute:   a.cfg.Detection.YARA.MaxScansPerMinute,
		YARAExcludePathPrefixes: a.cfg.Detection.YARA.ExcludePathPrefixes,
		BehavioralChainsPath:    behavioralChainsPath,
		CustomRulesPath:         customRulesPath,
		IOCHashDBPath:           a.cfg.Detection.IOC.HashDBPath,
		IOCIPDBPath:             a.cfg.Detection.IOC.IPDBPath,
		IOCDomainDBPath:         a.cfg.Detection.IOC.DomainDBPath,
		MLModelsDir:             a.cfg.ML.ModelsDir,
		WorkerCount:             a.cfg.Performance.WorkerCount,
		PerformanceProfile:      a.cfg.Performance.Profile,

		MLModelPEClassifier:    a.cfg.ML.Models.PEClassifier,
		MLModelBehaviorLSTM:    a.cfg.ML.Models.BehaviorLSTM,
		MLModelNetworkAnomaly:  a.cfg.ML.Models.NetworkAnomaly,
		MLModelNetworkLGBM:     a.cfg.ML.Models.NetworkLGBM,
		MLModelRansomware:      a.cfg.ML.Models.Ransomware,
		MLModelRATC2:           a.cfg.ML.Models.RATC2,

		MLThresholdPE:         float64(a.cfg.ML.Thresholds.PEMalicious),
		MLThresholdNetwork:    float64(a.cfg.ML.Thresholds.NetworkAnomaly),
		MLThresholdBehavior:   float64(a.cfg.ML.Thresholds.BehaviorAnomaly),
		MLThresholdRansomware: float64(a.cfg.ML.Thresholds.RansomwareScore),

		MLONNXNumThreads:  a.cfg.ML.ONNX.NumThreads,
		MLONNXUseGPU:      a.cfg.ML.ONNX.UseGPU,
		MLONNXGPUDeviceID: a.cfg.ML.ONNX.GPUDeviceID,

		MLVerifyPubKey: a.cfg.ML.VerifyPubKey,
	}

	ragCfg := a.cfg.LLM.RAG
	ragPath := ragCfg.VectorDBPath
	if ragCfg.Enabled {
		if ragPath == "" {
			dd := a.cfg.Agent.DataDir
			if dd == "" {
				dd = "/var/lib/edr"
			}
			ragPath = filepath.Join(dd, "rag")
		}
		topK := ragCfg.TopK
		if topK <= 0 {
			topK = 5
		}
		chunkSize := ragCfg.ChunkSize
		if chunkSize <= 0 {
			chunkSize = 512
		}
		kb := ragCfg.KnowledgeBases
		if len(kb) == 0 {
			kb = []string{"mitre_attack", "sigma_rules"}
		}
		ecfg.RAGEnabled = ragPath != ""
		ecfg.RAGStoragePath = ragPath
		ecfg.RAGKnowledgeBases = kb
		ecfg.RAGTopK = topK
		ecfg.RAGChunkSize = chunkSize
		ecfg.RAGEmbeddingModel = ragCfg.EmbeddingModel
	}

	eng, err := detection.NewEngine(ecfg, a.zapLogger)
	if err != nil {
		return fmt.Errorf("detection engine: %w", err)
	}
	a.advEngine = eng

	var llmProvider llm.Provider

	groqKey := os.Getenv("GROQ_API_KEY")
	if groqKey != "" {
		groqModel := a.cfg.LLM.Groq.Model
		if groqModel == "" {
			groqModel = "llama-3.1-8b-instant"
		}
		groqMaxTokens := a.cfg.LLM.Groq.MaxTokens
		if groqMaxTokens <= 0 {
			groqMaxTokens = 1024
		}
		llmProvider = providers.NewGroqProvider(groqKey, groqModel, "", groqMaxTokens)
		a.logger.Info("LLM provider configured", "provider", "groq", "model", groqModel, "max_tokens", groqMaxTokens)
	}

	if llmProvider == nil {
		grokKey := os.Getenv("GROK_API_KEY")
		if grokKey == "" {
			grokKey = a.cfg.LLM.Grok.APIKey
		}
		if grokKey != "" {
			grokModel := a.cfg.LLM.Grok.Model
			if grokModel == "" {
				grokModel = "grok-3-mini-fast"
			}
			llmProvider = providers.NewGrokProvider(grokKey, grokModel, "", 4096)
			a.logger.Info("LLM provider configured", "provider", "grok", "model", grokModel)
		}
	}

	if llmProvider != nil {
		llmEng, err := llm.NewEngine(llm.EngineConfig{
			Primary:       llmProvider,
			MaxConcurrent: 2,
		}, a.zapLogger)
		if err != nil {
			a.logger.Warn("llm engine init failed", "error", err)
		} else {
			a.llmEngine = llmEng
			a.advEngine.SetLLMEngine(llmEng)
			a.logger.Info("LLM analysis enabled", "provider", llmProvider.Name())
		}
	} else {
		a.logger.Info("LLM analysis disabled (no GROQ_API_KEY or GROK_API_KEY set)")
	}

	return nil
}

func applyRuntimeLimits(cfg config.Config, logger *slog.Logger) {
	if cfg.Performance.WorkerCount > 0 {
		maxProcs := cfg.Performance.WorkerCount
		if maxProcs > runtime.NumCPU() {
			maxProcs = runtime.NumCPU()
		}
		if maxProcs < 1 {
			maxProcs = 1
		}
		runtime.GOMAXPROCS(maxProcs)
	}

	if cfg.Performance.MaxMemoryMB > 0 {
		limit := int64(cfg.Performance.MaxMemoryMB) * 1024 * 1024
		debug.SetMemoryLimit(limit)
		if logger != nil {
			logger.Info("go runtime memory limit applied", "max_memory_mb", cfg.Performance.MaxMemoryMB)
		}
	}

	// Profile-aware GC: low_resource favours frequent small collections so RSS
	// stays close to live-set; strict favours throughput; balanced is between.
	gcPercent := 75
	switch strings.ToLower(strings.TrimSpace(cfg.Performance.Profile)) {
	case "low_resource":
		gcPercent = 50
	case "strict":
		gcPercent = 100
	}
	prev := debug.SetGCPercent(gcPercent)
	if logger != nil {
		logger.Info("go runtime gc percent applied",
			"profile", cfg.Performance.Profile,
			"gc_percent", gcPercent,
			"previous", prev)
	}
}

func normalizePerformanceProfile(cfg *config.Config) {
	if cfg == nil {
		return
	}
	profile := strings.ToLower(strings.TrimSpace(cfg.Performance.Profile))
	if profile == "" {
		profile = "balanced"
	}
	cfg.Performance.Profile = profile
	lowResource := profile == "low_resource" || (cfg.Performance.MaxMemoryMB > 0 && cfg.Performance.MaxMemoryMB <= 1024)

	if cfg.Performance.WorkerCount <= 0 {
		cfg.Performance.WorkerCount = 1
	}
	if lowResource && cfg.Performance.WorkerCount > 1 {
		cfg.Performance.WorkerCount = 1
	}
	if cfg.Performance.EventBufferSize <= 0 {
		cfg.Performance.EventBufferSize = 2048
	}
	if lowResource && cfg.Performance.EventBufferSize > 2048 {
		cfg.Performance.EventBufferSize = 2048
	}
	if cfg.Performance.BatchSize <= 0 {
		cfg.Performance.BatchSize = 20
	}
	if lowResource && cfg.Performance.BatchSize > 20 {
		cfg.Performance.BatchSize = 20
	}
	if lowResource && cfg.Detection.YARA.MaxFileSizeMB > 4 {
		cfg.Detection.YARA.MaxFileSizeMB = 4
	}
	if cfg.Detection.YARA.MaxFileSizeMB <= 0 {
		cfg.Detection.YARA.MaxFileSizeMB = 8
	}
	if cfg.Detection.YARA.RescanCooldownSec <= 0 {
		cfg.Detection.YARA.RescanCooldownSec = 120
	}
	if cfg.Detection.YARA.MaxScansPerMinute <= 0 {
		cfg.Detection.YARA.MaxScansPerMinute = 120
	}
	switch profile {
	case "strict":
		if cfg.Performance.WorkerCount < 2 {
			cfg.Performance.WorkerCount = 2
		}
		if cfg.Performance.EventBufferSize < 8192 {
			cfg.Performance.EventBufferSize = 8192
		}
		if cfg.Performance.BatchSize < 50 {
			cfg.Performance.BatchSize = 50
		}
		if cfg.Detection.YARA.RescanCooldownSec > 15 {
			cfg.Detection.YARA.RescanCooldownSec = 15
		}
		if cfg.Detection.YARA.MaxScansPerMinute < 600 {
			cfg.Detection.YARA.MaxScansPerMinute = 600
		}
	case "balanced":
		if cfg.Detection.YARA.RescanCooldownSec > 60 {
			cfg.Detection.YARA.RescanCooldownSec = 60
		}
		if cfg.Detection.YARA.MaxScansPerMinute < 240 {
			cfg.Detection.YARA.MaxScansPerMinute = 240
		}
	default: // low_resource
		if cfg.Detection.YARA.RescanCooldownSec < 120 {
			cfg.Detection.YARA.RescanCooldownSec = 120
		}
		if cfg.Detection.YARA.MaxScansPerMinute > 120 {
			cfg.Detection.YARA.MaxScansPerMinute = 120
		}
	}
}

func (a *Agent) initThreatIntel() error {
	ti := a.cfg.ThreatIntel
	if !ti.MISP.Enabled && !ti.OTX.Enabled && len(ti.CustomFeeds) == 0 {
		return nil
	}

	var matcher *ioc.Matcher
	if a.advEngine != nil {
		matcher = a.advEngine.EnsureIOCMatcher()
	} else {
		matcher = ioc.NewMatcher(a.zapLogger)
	}

	mgr := threatintel.NewManager(matcher, a.zapLogger)

	if ti.MISP.Enabled && ti.MISP.URL != "" && ti.MISP.APIKey != "" {
		mgr.RegisterFeed(threatintel.NewMISPClient(ti.MISP.URL, ti.MISP.APIKey, ti.MISP.VerifySSL))
		a.logger.Info("threat intel: MISP feed registered", "url", ti.MISP.URL)
	}

	if ti.OTX.Enabled && ti.OTX.APIKey != "" {
		mgr.RegisterFeed(threatintel.NewOTXClient(ti.OTX.APIKey))
		a.logger.Info("threat intel: OTX feed registered")
	}

	for _, cf := range ti.CustomFeeds {
		path := strings.TrimSpace(cf.URL)
		if path == "" {
			continue
		}
		if strings.HasPrefix(path, "file://") {
			localPath := strings.TrimPrefix(path, "file://")
			mgr.RegisterFeed(threatintel.NewLocalFeed(cf.Name, localPath, cf.Format))
			a.logger.Info("threat intel: local feed registered", "name", cf.Name, "path", localPath)
			continue
		}
		mgr.RegisterFeed(threatintel.NewFeedClient(cf.Name, path, cf.Format, cf.APIKey))
		a.logger.Info("threat intel: custom feed registered", "name", cf.Name, "format", cf.Format)
	}

	a.threatIntel = mgr
	return nil
}

func NewForTesting(cfg config.Config, rs rules.RuleSet) (*Agent, error) {
	pc, err := collector.NewProcessCollector(cfg.Service.EndpointID)
	if err != nil {
		return nil, err
	}
	return NewForTestingWithCollectors(cfg, rs, []collector.Collector{pc}), nil
}

func NewForTestingWithCollectors(cfg config.Config, rs rules.RuleSet, collectors []collector.Collector) *Agent {
	normalizePerformanceProfile(&cfg)
	a := &Agent{
		logger:             slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cfg:                cfg,
		collectors:         collectors,
		ruleSet:            rs,
		eventSpool:         spool.NewQueueWithLimit[schema.ProcessEvent](cfg.Performance.EventBufferSize),
		alertSpool:         spool.NewQueueWithLimit[schema.Alert](cfg.Performance.EventBufferSize),
		detector:           detect.NewEngine(rs),
		responder:          response.NewResponder(cfg.LegacyResponse.AllowKill, cfg.LegacyResponse.ProtectedProcesses),
		writer:             alert.NewWriter(cfg.Logging.AlertFile, cfg.Logging.AuditFile, 1024*1024),
		killAllow:          makeRuleAllowlist(cfg.LegacyResponse.KillRuleAllowlist),
		fileDedup:          collector.NewFileDeduper(0),
		fileHashPool:       newFileHashPool(),
		noisyAlertLastSeen: make(map[string]time.Time),
	}
	return a
}

func (a *Agent) Run(ctx context.Context) error {
	if len(a.collectors) == 0 {
		return errors.New("no collectors configured")
	}
	if a.cfg.Service.PIDFile != "" {
		if err := pidfile.Write(a.cfg.Service.PIDFile); err != nil {
			a.logger.Error("pidfile write failed", "path", a.cfg.Service.PIDFile, "error", err)
		} else {
			defer func() {
				_ = pidfile.Remove(a.cfg.Service.PIDFile)
			}()
		}
	}

	selfprotect.CheckPrivileges(a.zapLogger)

	if runtime.GOOS == "windows" && a.cfg.Monitoring.WindowsWDMProtectEnabled {
		if dev := strings.TrimSpace(a.cfg.Monitoring.WindowsWDMProtectDevice); dev != "" {
			kernel.GlobalWDMProtect().SetDevice(dev)
		}
		posture := kernel.RegisterCurrentProcessWithWDM()
		if conn, _ := posture["connected"].(bool); conn {
			a.logger.Info("wdm process protection active", "posture", posture)
		} else {
			a.logger.Warn("wdm process protection unavailable (install signed edr_protect.sys)", "posture", posture)
		}
	}

	if a.antiDebug != nil {
		go func() {
			if err := a.antiDebug.Start(ctx); err != nil && ctx.Err() == nil {
				a.logger.Error("anti-debugger exited", "error", err)
			}
		}()
	}
	if a.tamper != nil {
		go func() {
			if err := a.tamper.Start(ctx); err != nil && ctx.Err() == nil {
				a.logger.Error("tamper detector exited", "error", err)
			}
		}()
	}
	if a.integrity != nil {
		go func() {
			if err := a.integrity.Start(ctx); err != nil && ctx.Err() == nil {
				a.logger.Error("integrity checker exited", "error", err)
			}
		}()
	}

	for _, c := range a.collectors {
		if sc, ok := c.(collector.StartableCollector); ok {
			if err := sc.Start(ctx); err != nil {
				a.logger.Error("startable collector failed", "collector", sc.Name(), "error", err)
			} else {
				a.logger.Info("startable collector started", "collector", sc.Name())
				defer sc.Stop()
			}
		}
	}

	if a.mlAutoUpdater != nil {
		go a.mlAutoUpdater.Run(ctx)
		a.logger.Info("ml auto-updater started")
	}
	if a.feedbackIngester != nil {
		go a.feedbackIngester.Run(ctx.Done(), 0)
	}

	if a.durableSpool != nil {
		defer func() { _ = a.durableSpool.Close() }()
	}
	if a.telExporter != nil {
		defer func() { _ = a.telExporter.Flush() }()
	}
	if a.respEngine != nil {
		defer func() { _ = a.respEngine.Close() }()
	}

	if a.advEngine != nil {
		if err := a.advEngine.Start(ctx); err != nil {
			a.logger.Error("advanced detection engine start failed", "error", err)
		} else {
			a.logger.Info("advanced detection engine started",
				"llm_enabled", a.llmEngine != nil,
				"behavioral", true)
			defer func() { _ = a.advEngine.Stop() }()

			go a.drainAdvancedAlerts(ctx)
		}
	}

	if a.threatIntel != nil {
		if err := a.threatIntel.Start(ctx); err != nil {
			a.logger.Error("threat intel manager start failed", "error", err)
		} else {
			a.logger.Info("threat intel manager started")
			defer func() { _ = a.threatIntel.Stop() }()
		}
	}

	if a.baselineEngine != nil {
		a.logger.Info("baseline engine started",
			"learning_days", a.cfg.Baseline.LearningDays,
			"is_learning", a.baselineEngine.IsLearning())
		defer a.shutdownBaseline()
	}

	if a.scaRunner != nil {
		go func() {
			if err := a.scaRunner.Run(ctx); err != nil && ctx.Err() == nil {
				a.logger.Error("sca runner exited", "error", err)
			}
		}()
		a.logger.Info("compliance sca runner started")
	}

	a.logger.Info("agent started")
	a.logger.Info("rules loaded", "count", len(a.ruleSet.Rules))

	if a.responseLayer != nil {
		a.responseLayer.Start(ctx)
		defer a.responseLayer.Stop()
	}

	if a.controlPlane != nil {
		go a.runControlPlane(ctx)
	}

	a.runXDRBackground(ctx)

	if a.telemetryRelay != nil {
		go a.telemetryRelay.Run(ctx)
	}
	if a.userLookup != nil && runtime.GOOS == "linux" {
		go a.userLookup.WatchPasswd(ctx, a.logger)
	}

	ticker := time.NewTicker(a.cfg.Service.TickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent stopped")
			return nil
		case <-ticker.C:
			if err := a.ProcessCycle(ctx); err != nil {
				a.logger.Error("process cycle failed", "error", err)
			}
		}
	}
}

func (a *Agent) WriteMonitoringHealthSnapshot() {
	if a == nil {
		return
	}
	collector.WriteMonitoringHealth(a.cfg, a.collectors, a.logger)
}

// PrepareValidationHarness tunes agent behavior for cmd/agent --test-mode.
func (a *Agent) PrepareValidationHarness() {
	if a == nil {
		return
	}
	if a.cfg.Monitoring.HealthSnapshotSec <= 0 {
		a.cfg.Monitoring.HealthSnapshotSec = 5
	}
}

// ScanValidationYARA runs a synchronous YARA scan and forwards matches to the validation sink.
func (a *Agent) ScanValidationYARA(ctx context.Context, path string) {
	if a == nil || a.advEngine == nil {
		return
	}
	for _, d := range a.advEngine.ScanFileForValidation(ctx, path) {
		a.emitValidationDetection(d)
	}
}

// ProbeValidationFilePaths evaluates baseline file rules for validation harnesses.
func (a *Agent) ProbeValidationFilePaths(paths []string) {
	if a == nil || a.detector == nil {
		return
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		ev := schema.FileEvent{
			Path:      path,
			Operation: "open",
		}
		ev.EndpointID = a.cfg.Service.EndpointID
		_ = a.handleAlerts(a.detector.EvaluateFile(ev))
	}
}

func (a *Agent) emitValidationDetection(d detection.Detection) {
	if a == nil {
		return
	}
	a.validationMu.RLock()
	sink := a.validationSink
	a.validationMu.RUnlock()
	if sink != nil {
		sink(d)
	}
}

func (a *Agent) drainAdvancedAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case advAlert, ok := <-a.advEngine.Alerts():
			if !ok {
				return
			}
			if advAlert == nil {
				continue
			}
			d := detection.FromAlert(advAlert)
			a.emitValidationDetection(d)
			if a.responseLayer != nil {
				go func(det detection.Detection) {
					if err := a.responseLayer.Handle(ctx, det); err != nil {
						a.logger.Error("response layer handle failed", "error", err)
					}
				}(d)
			}
			al := schema.Alert{
				SchemaVersion: schema.SchemaVersionV1,
				AlertID:       advAlert.ID,
				RuleID:        advAlert.RuleID,
				EndpointID:    a.cfg.Service.EndpointID,
				Severity:      schema.Severity(advAlert.Severity),
				Score:         severityToScore(advAlert.Severity),
				Title:         advAlert.Title,
				Description:   advAlert.Description,
				Timestamp:     advAlert.Timestamp,
				FilePath:      advAlert.FilePath,
				FileSHA256:    advAlert.FileSHA256,
			}
			if pe, ok := advAlert.RawEvent.(*schema.ProcessEvent); ok {
				al.ProcessPID = pe.PID
				al.ProcessName = pe.ProcessName
				al.ProcessPath = pe.ProcessPath
				al.CommandLine = pe.CommandLine
			}
			if fe, ok := advAlert.RawEvent.(*schema.FileEvent); ok {
				if al.FilePath == "" {
					al.FilePath = fe.Path
				}
				if al.FileSHA256 == "" && fe.Hash != "" {
					al.FileSHA256 = fe.Hash
				}
				al.FileOperation = fe.Operation
				if al.ProcessPID == 0 && fe.ActorPID != 0 {
					al.ProcessPID = fe.ActorPID
				}
			}
			// handleAlerts can block on disk I/O; run concurrently so ctx cancellation
			// is still observed and Run() can finish defers (e.g. advEngine.Stop).
			errCh := make(chan error, 1)
			go func() {
				errCh <- a.handleAlerts([]schema.Alert{al})
			}()
			select {
			case <-ctx.Done():
				return
			case err := <-errCh:
				if err != nil {
					a.logger.Error("handle advanced alert failed", "error", err)
				}
				a.logger.Info("advanced detection alert",
					"rule", al.RuleID, "severity", al.Severity,
					"title", al.Title, "pid", al.ProcessPID,
					"file_path", al.FilePath, "file_sha256", al.FileSHA256)
			}
		}
	}
}

func severityToScore(s events.Severity) int {
	switch s {
	case events.SeverityCritical:
		return 100
	case events.SeverityHigh:
		return 80
	case events.SeverityMedium:
		return 60
	case events.SeverityLow:
		return 30
	default:
		return 10
	}
}

func (a *Agent) maybeForwardTelemetry(ctx context.Context, tel *collector.Telemetry) {
	if a.telemetryRelay == nil || tel == nil {
		return
	}
	line, err := collector.MarshalTelemetryLine(tel)
	if err != nil || len(line) == 0 {
		return
	}
	if err := a.telemetryRelay.TrySend(ctx, line); err != nil {
		a.telemetryRelay.Enqueue(line)
	}
}

func (a *Agent) ProcessCycle(ctx context.Context) error {
	if a.forwardDrain != nil {
		if err := a.forwardDrain.DrainPending(); err != nil {
			a.logger.Error("forwarder spool drain failed", "error", err)
		}
	}
	for _, c := range a.collectors {
		telemetries, err := c.Collect(ctx)
		if err != nil {
			return err
		}
		for i := range telemetries {
			tel := &telemetries[i]
			a.recordControlPlaneEvent()
			if tel.File != nil && a.fileDedup != nil {
				fe := tel.File
				if !a.fileDedup.ShouldEmitFile(fe.EventType, fe.ActorPID, fe.Path, fe.Operation) {
					continue
				}
			}
			collector.EnsureTelemetryOCSF(tel)
			a.maybeForwardTelemetry(ctx, tel)
			if tel.Fork != nil {
				ev := forkTelemetryToProcess(*tel.Fork)
				a.eventSpool.Push(ev)
				if err := a.handleAlerts(a.detector.EvaluateProcess(ev)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, tel.Fork)
				}
				if a.baselineEngine != nil {
					if err := a.handleAlerts(a.feedBaselineProcess(ev)); err != nil {
						return err
					}
				}
			}
			if tel.Process != nil {
				ev := *tel.Process
				a.eventSpool.Push(ev)
				if err := a.handleAlerts(a.detector.EvaluateProcess(ev)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &ev)
				}
				if a.baselineEngine != nil {
					if err := a.handleAlerts(a.feedBaselineProcess(ev)); err != nil {
						return err
					}
				}
			}
			if tel.Network != nil {
				ne := *tel.Network
				if err := a.handleAlerts(a.detector.EvaluateNetwork(ne)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &ne)
				}
				if a.baselineEngine != nil {
					if err := a.handleAlerts(a.feedBaselineNetwork(ne)); err != nil {
						return err
					}
				}
			}
			if tel.Auth != nil {
				ae := *tel.Auth
				if err := a.handleAlerts(a.detector.EvaluateAuth(ae)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &ae)
				}
				if a.baselineEngine != nil {
					if err := a.handleAlerts(a.feedBaselineAuth(ae)); err != nil {
						return err
					}
				}
			}
			if tel.Task != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Task.BaseEvent,
					ProcessName: "task_scheduler",
					ProcessPath: tel.Task.TaskName,
					CommandLine: tel.Task.Operation,
					User:        tel.Task.SubjectUser,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &pe)
				}
			}
			if tel.Service != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Service.BaseEvent,
					ProcessName: "service_install",
					ProcessPath: tel.Service.ImagePath,
					CommandLine: tel.Service.ServiceName,
					User:        tel.Service.AccountName,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &pe)
				}
			}
			if tel.Credential != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Credential.BaseEvent,
					PID:         int(tel.Credential.SourcePID),
					ProcessName: "credential_access",
					ProcessPath: tel.Credential.TargetPath,
					CommandLine: tel.Credential.Technique,
					User:        tel.Credential.SourceProcess,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &pe)
				}
			}
			if tel.Memory != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Memory.BaseEvent,
					PID:         int(tel.Memory.TargetPID),
					ProcessName: "memory_event",
					ProcessPath: tel.Memory.TargetProcess,
					CommandLine: tel.Memory.Operation,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, &pe)
				}
			}
			if tel.Container != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Container.BaseEvent,
					PID:         tel.Container.PID,
					ProcessName: "container_event",
					ProcessPath: tel.Container.Path,
					CommandLine: tel.Container.Operation,
					User:        tel.Container.ProcessName,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.SecPolicy != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.SecPolicy.BaseEvent,
					PID:         tel.SecPolicy.PID,
					ProcessName: "security_policy",
					CommandLine: tel.SecPolicy.Operation,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.Tamper != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Tamper.BaseEvent,
					ProcessName: "tamper",
					CommandLine: tel.Tamper.Message,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.Persistence != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Persistence.BaseEvent,
					PID:         int(tel.Persistence.PID),
					ProcessName: "persistence",
					ProcessPath: tel.Persistence.ExecutablePath,
					CommandLine: tel.Persistence.Technique,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.Privacy != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Privacy.BaseEvent,
					PID:         int(tel.Privacy.AccessingPID),
					ProcessName: "privacy",
					ProcessPath: tel.Privacy.AccessingProcess,
					CommandLine: tel.Privacy.Operation,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, tel.Privacy)
				}
			}
			if tel.Gatekeeper != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Gatekeeper.BaseEvent,
					PID:         int(tel.Gatekeeper.PID),
					ProcessName: "gatekeeper_bypass",
					ProcessPath: tel.Gatekeeper.FilePath,
					CommandLine: tel.Gatekeeper.ProcessPath,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.Dropped != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.Dropped.BaseEvent,
					ProcessName: "dropped_events",
					CommandLine: tel.Dropped.EventClass,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.TIStatus != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.TIStatus.BaseEvent,
					ProcessName: "ti_status",
					CommandLine: tel.TIStatus.Status + ":" + tel.TIStatus.Reason,
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.FeatureStatus != nil {
				pe := schema.ProcessEvent{
					BaseEvent:   tel.FeatureStatus.BaseEvent,
					ProcessName: "feature_status",
					CommandLine: "feature_coverage",
				}
				if err := a.handleAlerts(a.detector.EvaluateProcess(pe)); err != nil {
					return err
				}
			}
			if tel.File != nil {
				if err := a.handleAlerts(a.detector.EvaluateFile(*tel.File)); err != nil {
					return err
				}
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, tel.File)
				}
				if a.fileHashPool != nil {
					a.fileHashPool.Submit(tel.File)
				}
			}
			if tel.Registry != nil {
				if a.advEngine != nil {
					a.advEngine.Evaluate(ctx, tel.Registry)
				}
				shim := registryTelemetryToFile(*tel.Registry)
				if err := a.handleAlerts(a.detector.EvaluateFile(shim)); err != nil {
					return err
				}
			}
			if tel.Injection != nil && a.advEngine != nil {
				a.advEngine.Evaluate(ctx, tel.Injection)
			}
			if tel.Compliance != nil {
				if err := a.handleComplianceTelemetry(ctx, tel.Compliance); err != nil {
					return err
				}
			}
		}
	}

	if err := a.checkDriftAlerts(); err != nil {
		a.logger.Error("drift alert check failed", "error", err)
	}

	sec := a.cfg.Monitoring.HealthSnapshotSec
	if sec > 0 {
		a.healthMu.Lock()
		if time.Since(a.lastHealthSnapshot) >= time.Duration(sec)*time.Second {
			collector.WriteMonitoringHealth(a.cfg, a.collectors, a.logger)
			a.lastHealthSnapshot = time.Now()
		}
		a.healthMu.Unlock()
	}
	return nil
}

func (a *Agent) checkDriftAlerts() error {
	if a.driftDetector == nil {
		return nil
	}
	modelNames := []string{"pe_classifier", "behavior_lstm", "network_anomaly", "ransomware"}
	for _, name := range modelNames {
		if a.driftDetector.SampleCount(name) < 100 {
			continue
		}
		if !a.driftDetector.IsDrifting(name) {
			continue
		}
		featureDrift := a.driftDetector.FeatureDriftScore(name)
		predDrift := a.driftDetector.PredictionDriftScore(name)

		al := schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        "ml/drift-" + name,
			EndpointID:    a.cfg.Service.EndpointID,
			Severity:      schema.SeverityMedium,
			Score:         50,
			Title:         fmt.Sprintf("ML model drift detected: %s", name),
			Description: fmt.Sprintf(
				"Feature drift: %.2f, prediction drift: %.2f. Model may need retraining.",
				featureDrift, predDrift),
			Timestamp: time.Now().UTC(),
		}

		if err := a.handleAlerts([]schema.Alert{al}); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) handleAlerts(alerts []schema.Alert) error {
	productVersion := a.cfg.Agent.Version
	for i := range alerts {
		al := &alerts[i]
		ensureAlertOCSF(al, productVersion)
		a.emitValidationDetection(detection.FromSchemaAlert(*al))
		if a.shouldSuppressNoisyAlert(*al) {
			continue
		}
		correlationID := al.AlertID
		if correlationID == "" {
			correlationID = uuid.NewString()
			al.AlertID = correlationID
		}
		a.logger.Info("detection event",
			"event_type", "detection",
			"rule", al.RuleID,
			"target", firstNonEmpty(al.ProcessPath, al.FilePath, al.ProcessName),
			"result", "detected",
			"reason", al.Title,
			"correlation_id", correlationID)
		a.alertSpool.Push(*al)
		a.recordControlPlaneAlert()
		if a.durableSpool != nil {
			if data, err := marshalAlertOCSF(*al, productVersion); err == nil {
				if err := a.durableSpool.Write(data); err != nil {
					a.logger.Error("durable spool write failed", "error", err)
				}
			}
		}
		if err := a.writer.WriteAlert(*al); err != nil {
			return err
		}
		if a.forwarder != nil {
			if err := a.forwarder.Send(*al); err != nil {
				a.logger.Error("forward alert failed", "error", err)
			}
		}
		a.sendControlPlaneAlert(context.Background(), *al)
		a.executeAutoResponse(*al)
	}
	return nil
}

func (a *Agent) shouldSuppressNoisyAlert(al schema.Alert) bool {
	// Keep strict mode fully verbose; tune only low_resource/balanced.
	profile := strings.ToLower(strings.TrimSpace(a.cfg.Performance.Profile))
	if profile == "strict" {
		return false
	}
	if al.RuleID != "FILE-007" && al.RuleID != "CRED-001" {
		return false
	}
	target := strings.ToLower(strings.TrimSpace(firstNonEmpty(al.FilePath, al.ProcessPath, al.ProcessName)))
	if target == "" {
		return false
	}
	// High-frequency system file reads are expected on Linux hosts.
	if !strings.HasPrefix(target, "/etc/passwd") && !strings.HasPrefix(target, "/etc/shadow") {
		return false
	}
	cooldown := 30 * time.Second
	if profile == "low_resource" {
		cooldown = 2 * time.Minute
	}
	key := al.RuleID + "|" + target
	now := time.Now()
	a.noisyAlertMu.Lock()
	defer a.noisyAlertMu.Unlock()
	if last, ok := a.noisyAlertLastSeen[key]; ok && now.Sub(last) < cooldown {
		return true
	}
	a.noisyAlertLastSeen[key] = now
	if len(a.noisyAlertLastSeen) > 2048 {
		for k, ts := range a.noisyAlertLastSeen {
			if now.Sub(ts) > 10*cooldown {
				delete(a.noisyAlertLastSeen, k)
			}
		}
	}
	return false
}

func makeRuleAllowlist(ruleIDs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		out[id] = struct{}{}
	}
	return out
}

func (a *Agent) executeAutoResponse(al schema.Alert) {
	correlationID := al.AlertID
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	if !a.shouldAutoKill(al) {
		a.logger.Debug("response decision",
			"event_type", "response_decision",
			"rule", al.RuleID,
			"target", firstNonEmpty(al.ProcessPath, al.FilePath, al.ProcessName),
			"action", "none",
			"result", "skipped",
			"reason", "auto-kill policy did not match",
			"correlation_id", correlationID)
		return
	}

	if a.respEngine != nil {
		ctx := context.Background()
		if al.ProcessPID > 0 {
			params := map[string]interface{}{
				"pid":          al.ProcessPID,
				"process_name": al.ProcessName,
				"mode":         "kill",
				"tree":         al.Score >= 90,
			}
			result, err := a.respEngine.Execute(ctx, response.OpKillProcess, params)
			outcome := "failure"
			msg := ""
			if result != nil && result.Success {
				outcome = "success"
				msg = result.Message
			} else if err != nil {
				msg = err.Error()
			}

			_ = a.writer.WriteAudit(schema.AuditRecord{
				SchemaVersion: schema.SchemaVersionV1,
				RecordID:      uuid.NewString(),
				Action:        "kill_process",
				Outcome:       outcome,
				Message:       msg,
				Timestamp:     time.Now().UTC(),
			})
			a.logger.Info("response action outcome",
				"event_type", "response",
				"rule", al.RuleID,
				"target", firstNonEmpty(al.ProcessPath, al.FilePath, al.ProcessName),
				"action", "kill_process",
				"result", outcome,
				"reason", msg,
				"correlation_id", correlationID)
		}

		qPath := al.ProcessPath
		if qPath == "" {
			qPath = al.FilePath
		}
		if a.cfg.Response.Actions.QuarantineFile && qPath != "" {
			qParams := map[string]interface{}{
				"path":     qPath,
				"reason":   al.Title,
				"alert_id": al.AlertID,
			}
			if _, qErr := a.respEngine.Execute(ctx, response.OpQuarantineFile, qParams); qErr != nil {
				a.logger.Error("quarantine failed", "path", qPath, "error", qErr)
			} else {
				a.logger.Info("response action outcome",
					"event_type", "response",
					"rule", al.RuleID,
					"target", qPath,
					"action", "quarantine_file",
					"result", "success",
					"reason", al.Title,
					"correlation_id", correlationID)
			}
		}
		return
	}

	if al.ProcessPID <= 0 {
		return
	}

	res := a.responder.Execute(schema.ResponseCommand{
		SchemaVersion: schema.SchemaVersionV1,
		Action:        schema.ResponseKillProcess,
		ProcessPID:    al.ProcessPID,
		ProcessName:   al.ProcessName,
	})
	_ = a.writer.WriteAudit(schema.AuditRecord{
		SchemaVersion: schema.SchemaVersionV1,
		RecordID:      uuid.NewString(),
		Action:        "kill_process",
		Outcome:       map[bool]string{true: "success", false: "failure"}[res.Success],
		Message:       res.Message,
		Timestamp:     time.Now().UTC(),
	})
	a.logger.Info("response action outcome",
		"event_type", "response",
		"rule", al.RuleID,
		"target", firstNonEmpty(al.ProcessPath, al.FilePath, al.ProcessName),
		"action", "kill_process",
		"result", map[bool]string{true: "success", false: "failure"}[res.Success],
		"reason", res.Message,
		"correlation_id", correlationID)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (a *Agent) shouldAutoKill(al schema.Alert) bool {
	if !a.cfg.LegacyResponse.AllowKill || !a.cfg.LegacyResponse.AutoKillEnabled {
		return false
	}
	if al.Score < a.cfg.LegacyResponse.MinKillScore {
		return false
	}
	if len(a.killAllow) == 0 {
		return true
	}
	_, ok := a.killAllow[al.RuleID]
	return ok
}

// ---------------------------------------------------------------------------
// Self-protection
// ---------------------------------------------------------------------------

func (a *Agent) initSelfProtect() error {
	sp := a.cfg.SelfProtect
	if !sp.Enabled {
		return nil
	}

	if sp.AntiDebug {
		a.antiDebug = selfprotect.NewAntiDebugger(a.zapLogger)
		a.logger.Info("self-protection: anti-debug enabled")
	}

	if sp.IntegrityCheck {
		execPath, _ := os.Executable()
		paths := []string{}
		if execPath != "" {
			paths = append(paths, execPath)
		}
		if a.cfg.RulesFile != "" {
			paths = append(paths, a.cfg.RulesFile)
		}
		if len(paths) > 0 {
			backupDir := filepath.Join(a.cfg.Agent.DataDir, "integrity-backups")
			ic, err := selfprotect.NewIntegrityChecker(paths, backupDir, a.cfg.Agent.DataDir, a.zapLogger)
			if err != nil {
				a.logger.Warn("integrity checker init failed", "error", err)
			} else {
				a.integrity = ic
				a.logger.Info("self-protection: integrity checker enabled", "tracked_files", len(paths))
			}
		}
	}

	{
		ep, _ := os.Executable()
		protectedPaths := []string{}
		if ep != "" {
			protectedPaths = append(protectedPaths, ep)
		}
		// Do not watch alert/audit JSONL: the agent appends constantly; fsnotify would flag every write as tampering.
		if len(protectedPaths) > 0 {
			a.tamper = selfprotect.NewTamperDetector(protectedPaths, a.zapLogger)
			a.logger.Info("self-protection: tamper detector enabled", "watched_paths", len(protectedPaths))
		}
	}

	if sp.Watchdog {
		a.logger.Info("self-protection: watchdog enabled (managed externally)")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Response engine (full playbook-capable engine)
// ---------------------------------------------------------------------------

func (a *Agent) initResponseEngine() error {
	if !a.cfg.Response.AutoResponse {
		return nil
	}

	auditPath := a.cfg.Logging.AuditFile
	if auditPath == "" {
		auditPath = filepath.Join(a.cfg.Agent.DataDir, "audit.jsonl")
	}

	eng, err := response.NewResponseEngine(a.zapLogger, auditPath)
	if err != nil {
		return fmt.Errorf("response engine: %w", err)
	}

	eng.RegisterHandler(response.OpKillProcess,
		response.NewProcessHandler(a.zapLogger, a.cfg.LegacyResponse.ProtectedProcesses))
	eng.RegisterHandler(response.OpSuspendProcess,
		response.NewProcessHandler(a.zapLogger, a.cfg.LegacyResponse.ProtectedProcesses))

	qDir := a.cfg.Response.Quarantine.Dir
	if qDir == "" {
		qDir = filepath.Join(a.cfg.Agent.DataDir, "quarantine")
	}
	var encKey []byte
	if a.cfg.Response.Quarantine.EncryptFiles {
		h := sha256.Sum256([]byte("edr-quarantine-" + a.cfg.Service.EndpointID))
		encKey = h[:]
	}
	fh, err := response.NewFileHandler(a.zapLogger, qDir, encKey)
	if err != nil {
		a.logger.Warn("file handler init failed", "error", err)
	} else {
		eng.RegisterHandler(response.OpQuarantineFile, fh)
	}

	edrServer := a.cfg.Server.Endpoint
	if edrServer == "" {
		edrServer = "127.0.0.1"
	}
	eng.RegisterHandler(response.OpNetworkIsolate,
		response.NewNetworkHandler(a.zapLogger, edrServer, nil))
	eng.RegisterHandler(response.OpNetworkRelease,
		response.NewNetworkHandler(a.zapLogger, edrServer, nil))

	blockDBPath := filepath.Join(a.cfg.Agent.DataDir, "blocked_hashes.json")
	eng.RegisterHandler(response.OpBlockHash,
		response.NewBlockHashHandler(a.zapLogger, blockDBPath))

	a.respEngine = eng
	a.logger.Info("response engine initialized with playbook support")
	return nil
}

func (a *Agent) initResponseLayer() error {
	if a.respEngine == nil || !a.cfg.Response.AutoResponse {
		return nil
	}
	pp := a.cfg.Response.PlaybooksPath
	candidates := []string{}
	if pp != "" {
		candidates = append(candidates, pp)
		if !filepath.IsAbs(pp) {
			candidates = append(candidates, filepath.Join(a.cfg.Agent.DataDir, pp))
		}
	} else {
		if pd := strings.TrimSpace(a.cfg.Response.PlaybooksDir); pd != "" {
			candidates = append(candidates,
				filepath.Join(pd, "playbooks.yml"),
			)
			if !filepath.IsAbs(pd) {
				candidates = append(candidates, filepath.Join(a.cfg.Agent.DataDir, pd, "playbooks.yml"))
			}
		}
		candidates = append(candidates,
			filepath.Join("rules", "playbooks", "playbooks.yml"),
			filepath.Join(a.cfg.Agent.DataDir, "rules", "playbooks", "playbooks.yml"),
		)
	}
	var found string
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			found = c
			break
		}
	}
	if found == "" {
		a.logger.Info("YAML playbooks not loaded (file missing or not configured)", "candidates", candidates)
		return nil
	}
	pp = found
	fd := a.cfg.Response.ForensicsDir
	if fd == "" {
		fd = a.cfg.Response.Forensics.OutputDir
	}
	if fd == "" {
		fd = filepath.Join(a.cfg.Agent.DataDir, "forensics")
	}
	qd := a.cfg.Response.QuarantineDir
	if qd == "" {
		qd = a.cfg.Response.Quarantine.Dir
	}
	if qd == "" {
		qd = filepath.Join(a.cfg.Agent.DataDir, "quarantine")
	}
	agentIP := a.cfg.Server.Endpoint
	if agentIP == "" {
		agentIP = "127.0.0.1"
	}
	re, err := response.NewEngine(response.EngineConfig{
		PlaybooksPath: pp,
		ForensicsDir:  fd,
		QuarantineDir: qd,
		AgentIP:       agentIP,
		HostID:        a.cfg.Service.EndpointID,
		Logger:        a.zapLogger,
		ForensicsDeep: forensics.ForensicsDeepConfig{
			WindowsPrefetchEnabled:    a.cfg.Response.Forensics.WindowsPrefetchEnabled,
			WindowsAmcacheEnabled:     a.cfg.Response.Forensics.WindowsAmcacheEnabled,
			SelectedPageMemoryEnabled: a.cfg.Response.Forensics.SelectedPageMemoryEnabled,
			MacosTCCEnabled:           a.cfg.Response.Forensics.MacosTCCEnabled,
		},
		Approval: response.ApprovalConfig{
			Mode:               a.cfg.Response.Approval.Mode,
			WebhookURL:         a.cfg.Response.Approval.WebhookURL,
			CallbackURL:        a.cfg.Response.Approval.CallbackURL,
			CallbackListenAddr: a.cfg.Response.Approval.CallbackListenAddr,
			ApprovalDir:        a.cfg.Response.Approval.ApprovalDir,
			TimeoutSec:         a.cfg.Response.Approval.TimeoutSec,
		},
		ActionEng: a.respEngine,
	})
	if err != nil {
		return err
	}
	a.responseLayer = re
	a.logger.Info("response playbook layer ready", "playbooks", pp)
	return nil
}

// ---------------------------------------------------------------------------
// Baseline anomaly detection
// ---------------------------------------------------------------------------

func (a *Agent) initBaseline() error {
	if !a.cfg.Baseline.Enabled {
		return nil
	}

	storagePath := a.cfg.Baseline.StoragePath
	if storagePath == "" {
		dir := a.cfg.Agent.DataDir
		if dir == "" {
			dir = "/var/lib/edr"
		}
		storagePath = filepath.Join(dir, "baseline")
	}

	storage, err := baseline.NewBaselineStorage(storagePath, a.zapLogger)
	if err != nil {
		return fmt.Errorf("baseline storage: %w", err)
	}
	a.baselineStorage = storage

	learningDays := a.cfg.Baseline.LearningDays
	if learningDays <= 0 {
		learningDays = 7
	}

	engine := baseline.NewBaselineEngine(learningDays, a.zapLogger)
	if a.cfg.Baseline.DeviationMult > 0 {
		engine.SetDeviationMultiplier(a.cfg.Baseline.DeviationMult)
	}

	data, err := storage.Load()
	if err != nil {
		a.logger.Warn("baseline load failed, starting fresh", "error", err)
	} else if len(data) > 0 {
		engine.LoadBaselines(data)
		a.logger.Info("baseline data loaded", "categories", len(data))
	}

	a.baselineEngine = engine
	a.baselineNet = baseline.NewNetworkBaseline(engine, a.zapLogger)
	a.baselineProc = baseline.NewProcessBaseline(engine, a.zapLogger)
	a.baselineUser = baseline.NewUserBaseline(engine, a.zapLogger)

	storage.StartPeriodicSave(engine)
	return nil
}

func (a *Agent) shutdownBaseline() {
	if a.baselineStorage != nil {
		if err := a.baselineStorage.Close(); err != nil {
			a.logger.Error("baseline storage close failed", "error", err)
		}
	}
}

func (a *Agent) feedBaselineProcess(ev schema.ProcessEvent) []schema.Alert {
	a.baselineProc.Observe(baseline.ProcessObservation{
		ProcessName: ev.ProcessName,
		ParentName:  ev.ParentName,
		CommandLine: ev.CommandLine,
		PID:         ev.PID,
		PPID:        ev.PPID,
	})

	if a.baselineEngine.IsLearning() {
		return nil
	}

	var alerts []schema.Alert

	if ev.ParentName != "" && a.baselineProc.CheckParent(ev.ProcessName, ev.ParentName) {
		alerts = append(alerts, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        "baseline/unusual-parent",
			EndpointID:    a.cfg.Service.EndpointID,
			Severity:      schema.SeverityMedium,
			Score:         60,
			Title:         fmt.Sprintf("Unusual parent: %s spawned by %s", ev.ProcessName, ev.ParentName),
			Description:   fmt.Sprintf("Process %s was spawned by %s, not observed during baseline period", ev.ProcessName, ev.ParentName),
			Timestamp:     time.Now().UTC(),
			ProcessPID:    ev.PID,
			ProcessName:   ev.ProcessName,
			ProcessPath:   ev.ProcessPath,
			CommandLine:   ev.CommandLine,
		})
	}

	return alerts
}

func (a *Agent) feedBaselineNetwork(ev schema.NetworkEvent) []schema.Alert {
	a.baselineNet.Observe(baseline.NetworkObservation{
		SourceIP: ev.SourceIP,
		DestIP:   ev.DestIP,
		DestPort: ev.DestPt,
		Protocol: ev.Protocol,
		Domain:   ev.Domain,
	})

	if a.baselineEngine.IsLearning() {
		return nil
	}

	var alerts []schema.Alert

	if ev.DestIP != "" && a.baselineNet.CheckDestIP(ev.DestIP) {
		alerts = append(alerts, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        "baseline/new-dest-ip",
			EndpointID:    a.cfg.Service.EndpointID,
			Severity:      schema.SeverityLow,
			Score:         30,
			Title:         fmt.Sprintf("Connection to unseen IP %s", ev.DestIP),
			Description:   fmt.Sprintf("Network connection to %s:%d not observed during baseline period", ev.DestIP, ev.DestPt),
			Timestamp:     time.Now().UTC(),
			Protocol:      ev.Protocol,
			DestIP:        ev.DestIP,
			DestPort:      ev.DestPt,
		})
	}

	if ev.DestPt > 0 && a.baselineNet.CheckDestPort(ev.DestPt) {
		alerts = append(alerts, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        "baseline/new-dest-port",
			EndpointID:    a.cfg.Service.EndpointID,
			Severity:      schema.SeverityLow,
			Score:         30,
			Title:         fmt.Sprintf("Connection to unseen port %d", ev.DestPt),
			Description:   fmt.Sprintf("Network connection on port %d not observed during baseline period", ev.DestPt),
			Timestamp:     time.Now().UTC(),
			Protocol:      ev.Protocol,
			DestIP:        ev.DestIP,
			DestPort:      ev.DestPt,
		})
	}

	if ev.Domain != "" && a.baselineNet.CheckDNSQuery(ev.Domain) {
		alerts = append(alerts, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        "baseline/new-dns-query",
			EndpointID:    a.cfg.Service.EndpointID,
			Severity:      schema.SeverityLow,
			Score:         30,
			Title:         fmt.Sprintf("DNS query for unseen domain %s", ev.Domain),
			Description:   fmt.Sprintf("DNS query for %s not observed during baseline period", ev.Domain),
			Timestamp:     time.Now().UTC(),
			Domain:        ev.Domain,
			DestIP:        ev.DestIP,
			DestPort:      ev.DestPt,
		})
	}

	return alerts
}

func (a *Agent) feedBaselineAuth(ev schema.AuthEvent) []schema.Alert {
	a.baselineUser.Observe(baseline.UserObservation{
		Username:  ev.User,
		LoginTime: ev.Timestamp,
	})

	if a.baselineEngine.IsLearning() {
		return nil
	}

	var alerts []schema.Alert

	if ev.User != "" && !ev.Timestamp.IsZero() {
		if anomaly, deviation := a.baselineUser.CheckLoginTime(ev.User, ev.Timestamp); anomaly {
			alerts = append(alerts, schema.Alert{
				SchemaVersion: schema.SchemaVersionV1,
				AlertID:       uuid.NewString(),
				RuleID:        "baseline/unusual-login-time",
				EndpointID:    a.cfg.Service.EndpointID,
				Severity:      schema.SeverityMedium,
				Score:         60,
				Title:         fmt.Sprintf("Unusual login time for user %s", ev.User),
				Description:   fmt.Sprintf("User %s authenticated at hour %d (%.1f sigma deviation)", ev.User, ev.Timestamp.Hour(), deviation),
				Timestamp:     time.Now().UTC(),
				User:          ev.User,
				AuthType:      ev.AuthType,
				SourceIP:      ev.SourceIP,
			})
		}
	}

	return alerts
}

func forkTelemetryToProcess(fk schema.ForkEvent) schema.ProcessEvent {
	be := fk.BaseEvent
	be.EventType = schema.EventProcess
	return schema.ProcessEvent{
		BaseEvent:   be,
		PID:         fk.ParentPID,
		ChildPID:    fk.ChildPID,
		ProcessName: "fork",
		CommandLine: fmt.Sprintf("clone_flags=%d is_thread=%v is_container=%v", fk.CloneFlags, fk.IsThread, fk.IsContainer),
		CloneFlags:  fk.CloneFlags,
	}
}

func registryTelemetryToFile(re schema.RegistryEvent) schema.FileEvent {
	be := re.BaseEvent
	be.EventType = schema.EventFile
	path := re.KeyPath
	if re.ValueName != "" {
		path = path + `\` + re.ValueName
	}
	return schema.FileEvent{
		BaseEvent: be,
		Path:      path,
		Operation: re.Operation,
		ActorPID:  re.ActorPID,
	}
}
