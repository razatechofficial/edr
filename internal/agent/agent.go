package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/baseline"
	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detect"
	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/detection/ioc"
	"github.com/razatechofficial/edr/internal/detection/llm"
	"github.com/razatechofficial/edr/internal/detection/llm/providers"
	"github.com/razatechofficial/edr/internal/forwarder"
	"github.com/razatechofficial/edr/internal/pidfile"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/spool"
	"github.com/razatechofficial/edr/internal/threatintel"
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
}

func NewDefault() (*Agent, error) {
	return NewWithFiles("configs/agent.example.yaml")
}

func NewWithFiles(configPath string) (*Agent, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	cols, err := collector.DefaultCollectors(cfg.Service.EndpointID)
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

	zapLogger, _ := zap.NewProduction()

	a := &Agent{
		logger:     slog.Default(),
		cfg:        cfg,
		collectors: cols,
		ruleSet:    rs,
		eventSpool: spool.NewQueue[schema.ProcessEvent](),
		alertSpool: spool.NewQueue[schema.Alert](),
		detector:   detect.NewEngine(rs),
		responder:  response.NewResponder(cfg.LegacyResponse.AllowKill, cfg.LegacyResponse.ProtectedProcesses),
		writer:     alert.NewWriter(cfg.Logging.AlertFile, cfg.Logging.AuditFile, 5*1024*1024),
		killAllow:  makeRuleAllowlist(cfg.LegacyResponse.KillRuleAllowlist),
		zapLogger:  zapLogger,
	}

	if err := a.initAdvancedDetection(); err != nil {
		a.logger.Warn("advanced detection engine init failed, using basic rules only", "error", err)
	}

	if err := a.initThreatIntel(); err != nil {
		a.logger.Warn("threat intel init failed", "error", err)
	}

	if err := a.initBaseline(); err != nil {
		a.logger.Warn("baseline engine init failed", "error", err)
	}

	if cfg.Forwarder.Enabled {
		fw, dr, err := forwarder.New(forwarder.Config{
			Mode:         cfg.Forwarder.Mode,
			HTTPEndpoint: cfg.Forwarder.Endpoint,
			SyslogAddr:   cfg.Forwarder.SyslogAddr,
			KafkaBrokers: cfg.Forwarder.KafkaBrokers,
			KafkaTopic:   cfg.Forwarder.KafkaTopic,
			RetryMax:     cfg.Forwarder.RetryMax,
			SpoolPath:    cfg.Forwarder.SpoolPath,
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
	ecfg := detection.EngineConfig{
		BehavioralEnabled: true,
		SigmaEnabled:      a.cfg.Detection.Sigma.Enabled,
		YARAEnabled:       a.cfg.Detection.YARA.Enabled,
		IOCEnabled:        a.cfg.Detection.IOC.Enabled,
		MLEnabled:         a.cfg.ML.Enabled,
		LLMEnabled:        a.cfg.LLM.Enabled,
		SigmaRulesDir:     a.cfg.Detection.Sigma.RulesDir,
		YARARulesDir:      a.cfg.Detection.YARA.RulesDir,
		CustomRulesPath:   customRulesPath,
		IOCHashDBPath:     a.cfg.Detection.IOC.HashDBPath,
		IOCIPDBPath:       a.cfg.Detection.IOC.IPDBPath,
		IOCDomainDBPath:   a.cfg.Detection.IOC.DomainDBPath,
		MLModelsDir:       a.cfg.ML.ModelsDir,
		WorkerCount:       4,

		MLModelPEClassifier:   a.cfg.ML.Models.PEClassifier,
		MLModelBehaviorLSTM:   a.cfg.ML.Models.BehaviorLSTM,
		MLModelNetworkAnomaly: a.cfg.ML.Models.NetworkAnomaly,
		MLModelRansomware:     a.cfg.ML.Models.Ransomware,

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
		if cf.URL != "" {
			mgr.RegisterFeed(threatintel.NewFeedClient(cf.Name, cf.URL, cf.Format, cf.APIKey))
			a.logger.Info("threat intel: custom feed registered", "name", cf.Name, "format", cf.Format)
		}
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
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cfg:        cfg,
		collectors: collectors,
		ruleSet:    rs,
		eventSpool: spool.NewQueue[schema.ProcessEvent](),
		alertSpool: spool.NewQueue[schema.Alert](),
		detector:   detect.NewEngine(rs),
		responder:  response.NewResponder(cfg.LegacyResponse.AllowKill, cfg.LegacyResponse.ProtectedProcesses),
		writer:     alert.NewWriter(cfg.Logging.AlertFile, cfg.Logging.AuditFile, 1024*1024),
		killAllow:  makeRuleAllowlist(cfg.LegacyResponse.KillRuleAllowlist),
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

	a.logger.Info("agent started")
	a.logger.Info("rules loaded", "count", len(a.ruleSet.Rules))

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

func (a *Agent) drainAdvancedAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case advAlert, ok := <-a.advEngine.Alerts():
			if !ok {
				return
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
			}
			if pe, ok := advAlert.RawEvent.(*schema.ProcessEvent); ok {
				al.ProcessPID = pe.PID
				al.ProcessName = pe.ProcessName
				al.ProcessPath = pe.ProcessPath
				al.CommandLine = pe.CommandLine
			}
			_ = a.writer.WriteAlert(al)
			a.alertSpool.Push(al)
			a.logger.Info("advanced detection alert",
				"rule", al.RuleID, "severity", al.Severity,
				"title", al.Title, "pid", al.ProcessPID)
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
		for _, tel := range telemetries {
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
				if a.baselineEngine != nil {
					if err := a.handleAlerts(a.feedBaselineAuth(ae)); err != nil {
						return err
					}
				}
			}
			if tel.File != nil {
				if err := a.handleAlerts(a.detector.EvaluateFile(*tel.File)); err != nil {
					return err
				}
				if a.advEngine != nil {
					fe := *tel.File
					a.advEngine.Evaluate(ctx, &fe)
				}
			}
		}
	}
	return nil
}

func (a *Agent) handleAlerts(alerts []schema.Alert) error {
	for _, al := range alerts {
		a.alertSpool.Push(al)
		if err := a.writer.WriteAlert(al); err != nil {
			return err
		}
		if a.forwarder != nil {
			if err := a.forwarder.Send(al); err != nil {
				a.logger.Error("forward alert failed", "error", err)
			}
		}
		if a.shouldAutoKill(al) {
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
		}
	}
	return nil
}

func makeRuleAllowlist(ruleIDs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		out[id] = struct{}{}
	}
	return out
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
