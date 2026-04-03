package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detect"
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
}

func NewDefault() (*Agent, error) {
	cfg, err := config.Load("configs/agent.example.yaml")
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
	return &Agent{
		logger:     slog.Default(),
		cfg:        cfg,
		collectors: []collector.Collector{pc},
		ruleSet:    rs,
		eventSpool: spool.NewQueue[schema.ProcessEvent](),
		alertSpool: spool.NewQueue[schema.Alert](),
		detector:   detect.NewEngine(rs),
		responder:  response.NewResponder(cfg.Response.AllowKill, cfg.Response.ProtectedProcesses),
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if len(a.collectors) == 0 {
		return errors.New("no collectors configured")
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
			for _, c := range a.collectors {
				events, err := c.Collect(ctx)
				if err != nil {
					a.logger.Error("collect failed", "collector", c.Name(), "error", err)
					continue
				}
				for _, ev := range events {
					a.eventSpool.Push(ev)
					alerts := a.detector.EvaluateProcess(ev)
					for _, al := range alerts {
						a.alertSpool.Push(al)
						if al.Severity == schema.SeverityCritical {
							res := a.responder.Execute(schema.ResponseCommand{
								SchemaVersion: schema.SchemaVersionV1,
								Action:        schema.ResponseKillProcess,
								ProcessPID:    al.ProcessPID,
								FilePath:      al.ProcessName,
							})
							a.logger.Info("response executed", "success", res.Success, "msg", res.Message)
						}
					}
				}
			}
		}
	}
}
