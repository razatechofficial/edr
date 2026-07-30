package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	telemetryv1 "github.com/razatechofficial/xdr/api/proto/telemetry/v1"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/forwarder"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/telemetryqueue"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func (a *Agent) initXDR() error {
	if !xdrclient.ShouldInitXDR(a.cfg.XDR, a.cfg.Agent.DataDir) {
		return nil
	}

	boot, err := xdrclient.ApplyBootstrap(&a.cfg.XDR, xdrclient.BootstrapOverrides{
		ConfigDir: filepath.Dir(a.configPath),
		DataDir:   a.cfg.Agent.DataDir,
	})
	if err != nil {
		return fmt.Errorf("xdr bootstrap: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := xdrclient.EnsureEnrolled(ctx, xdrclient.EnrollOptions{
		Config:        a.cfg.XDR,
		AgentID:       a.cfg.Agent.ID,
		AgentVer:      a.cfg.Agent.Version,
		DataDir:       a.cfg.Agent.DataDir,
		Logger:        a.logger,
		ConfigPath:    a.configPath,
		TokenFileUsed: boot.TokenFileUsed,
	})
	if err != nil {
		return fmt.Errorf("xdr enroll: %w", err)
	}
	// Drop bootstrap token from in-memory config after successful enroll.
	if res.Fresh {
		a.cfg.XDR.EnrollmentToken = ""
	}
	a.xdrStore = res.Store
	a.xdrState = res.State
	// Ingest mTLS pins identity to the device cert CN. Always use the enrolled
	// agent_id (from enrollment.json / cert), never a fresh local UUID that may
	// differ after resume-without-token.
	if id := strings.TrimSpace(res.State.AgentID); id != "" {
		if a.cfg.Agent.ID != id {
			a.logger.Info("pinning agent identity to enrolled certificate",
				"previous_agent_id", a.cfg.Agent.ID,
				"enrolled_agent_id", id,
			)
			a.cfg.Agent.ID = id
		}
		// Keep data_dir/agent_id in sync so next boot does not regenerate a mismatch.
		_ = os.WriteFile(filepath.Join(a.cfg.Agent.DataDir, "agent_id"), []byte(id+"\n"), 0o600)
	}

	maxBytes := a.cfg.XDR.SpoolMaxBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 30
	}
	qdir := filepath.Join(a.cfg.Agent.DataDir, "telemetry-queue")
	qm, qerr := telemetryqueue.NewManager(qdir, maxBytes)
	if qerr != nil {
		return fmt.Errorf("xdr telemetry queue: %w", qerr)
	}
	if days := a.cfg.XDR.SpoolMaxAgeDays; days > 0 {
		if n := qm.PurgeOlderThan(time.Duration(days) * 24 * time.Hour); n > 0 {
			a.logger.Info("purged expired telemetry spool segments", "count", n, "max_age_days", days)
		}
	}

	ingest := xdrclient.NewIngestClient(
		res.State.IngestHosts,
		res.State.AgentID,
		res.Store,
		a.cfg.XDR.InsecureSkipTLS,
		res.State.HeartbeatSec,
		a.logger,
	)
	ingest.SetCommandHandler(a.handleIngestCommand)
	ingest.SetPostureProvider(func() map[string]string {
		return collector.FleetPostureLabels(a.cfg)
	})
	a.xdrIngest = ingest
	a.telemetryRelay = forwarder.NewTelemetryRelayWithSender(ingest, qm, a.logger)
	a.logger.Info("xdr ingest telemetry relay configured",
		"hosts", res.State.IngestHosts,
		"queue_dir", qdir,
	)
	return nil
}

func (a *Agent) runXDRBackground(ctx context.Context) {
	if a.xdrIngest != nil {
		go a.xdrIngest.RunHeartbeat(ctx)
	}
	if a.xdrStore.Dir == "" || a.cfg.XDR.EnrollmentHost == "" {
		return
	}
	go xdrclient.WatchAndRenew(ctx, xdrclient.RenewOptions{
		Config:   a.cfg.XDR,
		State:    a.xdrState,
		Store:    a.xdrStore,
		AgentVer: a.cfg.Agent.Version,
		Logger:   a.logger,
	}, func(st xdrclient.State) {
		a.xdrState = st
		a.logger.Info("xdr cert hot-reloaded; next ingest reconnect will use new cert")
		if a.xdrIngest != nil {
			_ = a.xdrIngest.Close()
		}
	})
}

func (a *Agent) handleIngestCommand(ctx context.Context, cmd *telemetryv1.AgentCommand) error {
	if a == nil || cmd == nil {
		return fmt.Errorf("nil command")
	}
	if a.respEngine == nil {
		return fmt.Errorf("response engine unavailable")
	}
	op := response.OpKey(xdrclient.MapRemoteCommandType(cmd.GetType()))
	params := xdrclient.ParseCommandPayload(cmd.GetPayload())
	if op == response.OpNetworkIsolate {
		if _, ok := params["action"]; !ok {
			params["action"] = "isolate"
		}
	}
	result, err := a.respEngine.Execute(ctx, op, params)
	if err != nil {
		return err
	}
	if result != nil && !result.Success {
		return fmt.Errorf("%s", result.Message)
	}
	return nil
}
