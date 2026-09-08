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
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/forwarder"
	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/telemetryqueue"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func (a *Agent) initXDR() error {
	if !xdrclient.ShouldInitXDR(a.cfg.XDR, a.cfg.Agent.DataDir) {
		return fmt.Errorf("xdr ingest not configured (enabled=%v storage=%s data_dir=%s)",
			a.cfg.XDR.Enabled, a.cfg.XDR.SecureStorage, a.cfg.Agent.DataDir)
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

	store := xdrclient.Store{
		Dir:     xdrclient.ResolveCertDir(a.cfg.XDR, a.cfg.Agent.DataDir),
		DataDir: a.cfg.Agent.DataDir,
		Backend: a.cfg.XDR.SecureStorage,
	}.WithExistingCredentials()
	a.cfg.XDR.SecureStorage = store.BackendName()

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
		if fallback, ferr := resumeIngestFromCert(store, a.cfg.XDR, a.cfg.Agent.ID); ferr == nil {
			a.logger.Warn("xdr enroll resume failed; starting ingest from existing device cert", "error", err)
			res = fallback
			err = nil
		} else {
			return fmt.Errorf("xdr enroll: %w", err)
		}
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

	qm, qdir := openIngestQueue(a.cfg.Agent.DataDir, a.cfg.XDR.SpoolMaxBytes, a.logger)
	if qm != nil && a.cfg.XDR.SpoolMaxAgeDays > 0 {
		if n := qm.PurgeOlderThan(time.Duration(a.cfg.XDR.SpoolMaxAgeDays) * 24 * time.Hour); n > 0 {
			a.logger.Info("purged expired telemetry spool segments", "count", n, "max_age_days", a.cfg.XDR.SpoolMaxAgeDays)
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
	if err := xdrclient.EnsureTrustCA(ctx, res.Store, a.cfg.XDR.EnrollmentHost, a.cfg.XDR.InsecureSkipTLS); err != nil {
		a.logger.Warn("xdr trust CA missing; ingest mTLS may fail", "error", err)
	}
	a.xdrIngest = ingest
	a.telemetryRelay = forwarder.NewTelemetryRelayWithSender(ingest, qm, a.logger)
	persistXDRInitNote(a.cfg, "ingest client started host="+strings.Join(res.State.IngestHosts, ","))
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer connectCancel()
	if err := ingest.Connect(connectCtx); err != nil {
		a.logger.Warn("xdr ingest did not connect on start; heartbeat will retry", "error", err)
	} else {
		a.logger.Info("xdr ingest stream connected")
	}
	a.logger.Info("xdr ingest telemetry relay configured",
		"hosts", res.State.IngestHosts,
		"queue_dir", qdir,
	)
	return nil
}

// openIngestQueue prefers the durable spool, then a fresh sibling folder, then
// %TEMP%. A locked telemetry-queue must not block the ingest stream.
func openIngestQueue(dataDir string, spoolMax int64, log interface {
	Warn(msg string, args ...any)
}) (*telemetryqueue.Manager, string) {
	maxBytes := telemetryqueue.EffectiveMaxBytes(spoolMax)
	dd := strings.TrimSpace(dataDir)
	if dd == "" {
		dd = platform.DataDir()
	}
	dirs := []string{
		filepath.Join(dd, "telemetry-queue"),
		filepath.Join(dd, "telemetry-spool"),
		filepath.Join(os.TempDir(), "edr-agent-telemetry-queue"),
	}
	var last error
	for _, dir := range dirs {
		qm, err := telemetryqueue.NewManager(dir, maxBytes)
		if err == nil {
			if dir != dirs[0] && log != nil {
				log.Warn("xdr telemetry queue using fallback path", "dir", dir)
			}
			return qm, dir
		}
		last = err
		if log != nil {
			log.Warn("xdr telemetry queue unavailable", "dir", dir, "error", err)
		}
	}
	if last != nil && log != nil {
		log.Warn("xdr ingest continuing without a disk spool", "error", last)
	}
	return nil, ""
}

func (a *Agent) runXDRBackground(ctx context.Context) {
	if a.xdrIngest != nil {
		go a.xdrIngest.RunHeartbeat(ctx)
	}
	go a.watchLateIngest(ctx)
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

// watchLateIngest starts the ingest client after enroll writes a cert while
// the sensor is already running. Windows MSI starts EDRAgent before Enroll;
// if service stop does not recycle the process, ingest stayed nil forever.
func (a *Agent) watchLateIngest(ctx context.Context) {
	t := time.NewTicker(4 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.xdrMu.Lock()
			ready := a.xdrIngest != nil
			a.xdrMu.Unlock()
			if ready {
				continue
			}
			if !xdrclient.ShouldInitXDR(a.cfg.XDR, a.cfg.Agent.DataDir) {
				continue
			}
			if err := a.ensureIngest(ctx); err != nil {
				a.logger.Info("xdr ingest still deferred", "error", err)
			}
		}
	}
}

func (a *Agent) ensureIngest(ctx context.Context) error {
	a.xdrMu.Lock()
	defer a.xdrMu.Unlock()
	if a.xdrIngest != nil {
		cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return a.xdrIngest.Connect(cctx)
	}
	if err := a.initXDR(); err != nil {
		persistXDRInitFault(a.cfg, err.Error())
		return err
	}
	if a.xdrIngest != nil {
		go a.xdrIngest.RunHeartbeat(ctx)
	}
	return nil
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

func persistXDRInitNote(cfg config.Config, detail string) {
	dd := strings.TrimSpace(cfg.Agent.DataDir)
	if dd == "" {
		dd = platform.DataDir()
	}
	_ = os.WriteFile(filepath.Join(dd, "xdr.init"), []byte(detail+"\n"), 0o644)
}

func persistXDRInitFault(cfg config.Config, detail string) {
	dd := strings.TrimSpace(cfg.Agent.DataDir)
	if dd == "" {
		dd = platform.DataDir()
	}
	certDir := xdrclient.ResolveCertDir(cfg.XDR, dd)
	xdrclient.PersistIngestStatus(certDir, false, "", detail)
	xdrclient.PersistIngestStatus(dd, false, "", detail)
	persistXDRInitNote(cfg, detail)
}

func resumeIngestFromCert(store xdrclient.Store, cfg config.XDRConfig, agentID string) (*xdrclient.EnrollResult, error) {
	store = store.WithExistingCredentials()
	if !store.HasCredentials() {
		return nil, fmt.Errorf("no device certificate")
	}
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(st.AgentID) == "" {
		st.AgentID = strings.TrimSpace(agentID)
	}
	if len(st.IngestHosts) == 0 {
		st.IngestHosts = xdrclient.DefaultIngestHosts()
	}
	return &xdrclient.EnrollResult{State: st, Store: store, Fresh: false}, nil
}
