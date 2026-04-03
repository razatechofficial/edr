package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detect"
	"github.com/razatechofficial/edr/internal/forwarder"
	"github.com/razatechofficial/edr/internal/pidfile"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/spool"
)

type Agent struct {
	logger     *slog.Logger
	cfg        config.Config
	collectors []collector.Collector
	ruleSet    rules.RuleSet
	eventSpool *spool.Queue[schema.ProcessEvent]
	alertSpool *spool.Queue[schema.Alert]
	detector   *detect.Engine
	responder  *response.Responder
	writer     *alert.Writer
	forwarder  forwarder.Forwarder
	killAllow  map[string]struct{}
}

func NewDefault() (*Agent, error) {
	return NewWithFiles("configs/agent.example.yaml")
}

func NewWithFiles(configPath string) (*Agent, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	pc, err := collector.NewProcessCollector(cfg.Service.EndpointID)
	if err != nil {
		return nil, err
	}
	rs, err := rules.Load(cfg.RulesFile)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		logger:     slog.Default(),
		cfg:        cfg,
		collectors: []collector.Collector{pc},
		ruleSet:    rs,
		eventSpool: spool.NewQueue[schema.ProcessEvent](),
		alertSpool: spool.NewQueue[schema.Alert](),
		detector:   detect.NewEngine(rs),
		responder:  response.NewResponder(cfg.Response.AllowKill, cfg.Response.ProtectedProcesses),
		writer:     alert.NewWriter(cfg.Logging.AlertFile, cfg.Logging.AuditFile, 5*1024*1024),
		killAllow:  makeRuleAllowlist(cfg.Response.KillRuleAllowlist),
	}
	if cfg.Forwarder.Enabled {
		fw, err := forwarder.New(cfg.Forwarder.Mode, cfg.Forwarder.Endpoint, a.logger)
		if err != nil {
			return nil, err
		}
		a.forwarder = fw
	}
	return a, nil
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
		responder:  response.NewResponder(cfg.Response.AllowKill, cfg.Response.ProtectedProcesses),
		writer:     alert.NewWriter(cfg.Logging.AlertFile, cfg.Logging.AuditFile, 1024*1024),
		killAllow:  makeRuleAllowlist(cfg.Response.KillRuleAllowlist),
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

func (a *Agent) ProcessCycle(ctx context.Context) error {
	for _, c := range a.collectors {
		events, err := c.Collect(ctx)
		if err != nil {
			return err
		}
		for _, ev := range events {
			a.eventSpool.Push(ev)
			alerts := a.detector.EvaluateProcess(ev)
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
	if !a.cfg.Response.AllowKill || !a.cfg.Response.AutoKillEnabled {
		return false
	}
	if al.Score < a.cfg.Response.MinKillScore {
		return false
	}
	if len(a.killAllow) == 0 {
		return true
	}
	_, ok := a.killAllow[al.RuleID]
	return ok
}
