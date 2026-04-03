package agent

import (
	"context"
	"log/slog"
)

type Agent struct {
	logger *slog.Logger
}

func NewDefault() (*Agent, error) {
	return &Agent{logger: slog.Default()}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent started")
	<-ctx.Done()
	a.logger.Info("agent stopped")
	return nil
}
