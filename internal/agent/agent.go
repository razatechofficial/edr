package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detect"
	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/detection/llm"
	"github.com/razatechofficial/edr/internal/detection/llm/providers"
	"github.com/razatechofficial/edr/internal/forwarder"
	"github.com/razatechofficial/edr/internal/pidfile"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/spool"
	"github.com/razatechofficial/edr/pkg/events"
)

type Agent struct {
	logger     *slog.Logger
	cfg        config.Config
	collectors []collector.Collector
	ruleSet    rules.RuleSet
	eventSpool *spool.Queue[schema.ProcessEvent]
	alertSpool *spool.Queue[schema.Alert]
	detector   *detect.Engine
	advEngine  *detection.Engine
	llmEngine  *llm.Engine
	responder  *response.Responder
	writer     *alert.Writer
	forwarder  forwarder.Forwarder
	forwardDrain forwarder.Drainer
	killAllow  map[string]struct{}
	zapLogger  *zap.Logger
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
	ecfg := detection.EngineConfig{
		BehavioralEnabled: true,
		SigmaEnabled:      a.cfg.Detection.Sigma.Enabled,
		YARAEnabled:       a.cfg.Detection.YARA.Enabled,
		IOCEnabled:        a.cfg.Detection.IOC.Enabled,
		MLEnabled:         a.cfg.ML.Enabled,
		LLMEnabled:        a.cfg.LLM.Enabled,
		SigmaRulesDir:     a.cfg.Detection.Sigma.RulesDir,
		YARARulesDir:      a.cfg.Detection.YARA.RulesDir,
		IOCHashDBPath:     a.cfg.Detection.IOC.HashDBPath,
		IOCIPDBPath:       a.cfg.Detection.IOC.IPDBPath,
		IOCDomainDBPath:   a.cfg.Detection.IOC.DomainDBPath,
		MLModelsDir:       a.cfg.ML.ModelsDir,
		WorkerCount:       4,
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
			}
			if tel.Network != nil {
				if err := a.handleAlerts(a.detector.EvaluateNetwork(*tel.Network)); err != nil {
					return err
				}
				if a.advEngine != nil {
					ne := *tel.Network
					a.advEngine.Evaluate(ctx, &ne)
				}
			}
			if tel.Auth != nil {
				if err := a.handleAlerts(a.detector.EvaluateAuth(*tel.Auth)); err != nil {
					return err
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
