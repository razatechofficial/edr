package agent

import (
	"context"
	"os"

	"github.com/razatechofficial/edr/internal/comms"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/protocol"
)

func (a *Agent) initControlPlane() error {
	if a == nil {
		return nil
	}
	hostname, _ := os.Hostname()
	cp, err := comms.NewControlPlane(comms.ControlPlaneConfig{
		ServerHost:   a.cfg.Server.Endpoint,
		GRPCPort:     a.cfg.Server.GRPCPort,
		AgentID:      a.cfg.Agent.ID,
		Version:      a.cfg.Agent.Version,
		Hostname:     hostname,
		TLSCertPath:  a.cfg.Server.TLSCertPath,
		TLSKeyPath:   a.cfg.Server.TLSKeyPath,
		CACertPath:   a.cfg.Server.CACertPath,
		MutualTLS:    a.cfg.Server.MutualTLS,
		HeartbeatSec: a.cfg.Server.HeartbeatSec,
		ReconnectSec: a.cfg.Server.ReconnectSec,
		AirGapMode:   a.cfg.Server.AirGapMode,
	}, a.zapLogger)
	if err != nil {
		return err
	}
	if cp == nil {
		return nil
	}
	cp.SetRulesLoaded(func() int {
		return len(a.ruleSet.Rules)
	})
	cp.SetCommandDispatch(func(ctx context.Context, cmd *protocol.Command) error {
		if a.respEngine == nil {
			return comms.ExecuteProtoCommand(ctx, nil, cmd, a.zapLogger)
		}
		return comms.ExecuteProtoCommand(ctx, a.respEngine, cmd, a.zapLogger)
	})
	a.controlPlane = cp
	a.logger.Info("gRPC control plane configured",
		"server", a.cfg.Server.Endpoint,
		"port", a.cfg.Server.GRPCPort,
		"agent_id", a.cfg.Agent.ID,
	)
	return nil
}

func (a *Agent) startControlPlane(ctx context.Context) error {
	if a == nil || a.controlPlane == nil {
		return nil
	}
	return a.controlPlane.Start(ctx)
}

func (a *Agent) stopControlPlane() {
	if a == nil || a.controlPlane == nil {
		return
	}
	a.controlPlane.Stop()
}

func (a *Agent) recordControlPlaneEvent() {
	if hb := a.controlPlaneHeartbeat(); hb != nil {
		hb.RecordEvent()
	}
}

func (a *Agent) recordControlPlaneAlert() {
	if hb := a.controlPlaneHeartbeat(); hb != nil {
		hb.RecordAlert()
	}
}

func (a *Agent) controlPlaneHeartbeat() *comms.Heartbeat {
	if a == nil || a.controlPlane == nil {
		return nil
	}
	return a.controlPlane.Heartbeat()
}

func (a *Agent) sendControlPlaneAlert(ctx context.Context, al schema.Alert) {
	if a == nil || a.controlPlane == nil {
		return
	}
	if al.Severity != schema.SeverityCritical && al.Severity != schema.SeverityHigh {
		return
	}
	if err := a.controlPlane.SendAlert(ctx, al, a.cfg.Agent.Version); err != nil {
		a.logger.Error("control plane alert send failed", "error", err, "alert_id", al.AlertID)
	}
}
