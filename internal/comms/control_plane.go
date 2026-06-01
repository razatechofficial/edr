package comms

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"

	alertpkg "github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"github.com/razatechofficial/edr/pkg/protocol"
)

// ControlPlaneConfig configures the agent gRPC control-plane client.
type ControlPlaneConfig struct {
	ServerHost   string
	GRPCPort     int
	AgentID      string
	Version      string
	Commit       string
	Hostname     string
	TLSCertPath  string
	TLSKeyPath   string
	CACertPath   string
	MutualTLS    bool
	HeartbeatSec int
	ReconnectSec int
	AirGapMode   bool
	PolicySyncSec int
}

// CommandDispatch executes a server-issued command on the agent.
type CommandDispatch func(ctx context.Context, cmd *protocol.Command) error

// ControlPlane orchestrates gRPC registration, heartbeat, streaming, and alerts.
type ControlPlane struct {
	client    *GRPCClient
	heartbeat *Heartbeat
	logger    *zap.Logger

	registerMeta registrationMeta
	reconnectSec time.Duration
	heartbeatSec time.Duration

	rulesLoaded func() int
	dispatch    CommandDispatch
	policyApply PolicyApplyFunc
	policyHashFn PolicyHashFunc
	policySyncSec time.Duration

	startTime time.Time

	mu        sync.RWMutex
	connected bool

	stopOnce sync.Once
	stopCh   chan struct{}
}

type registrationMeta struct {
	agentID  string
	hostname string
	version  string
	commit   string
}

// NewControlPlane builds a control-plane client. Returns (nil, nil) when disabled.
func NewControlPlane(cfg ControlPlaneConfig, logger *zap.Logger) (*ControlPlane, error) {
	if !controlPlaneEnabled(cfg) {
		return nil, nil
	}
	if cfg.AgentID == "" {
		return nil, fmt.Errorf("control_plane: agent_id is required")
	}
	if cfg.Hostname == "" {
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("control_plane: hostname: %w", err)
		}
		cfg.Hostname = host
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 30
	}
	if cfg.ReconnectSec <= 0 {
		cfg.ReconnectSec = 5
	}
	policySyncSec := time.Duration(cfg.PolicySyncSec) * time.Second
	if policySyncSec <= 0 {
		policySyncSec = time.Duration(cfg.HeartbeatSec*2) * time.Second
		if policySyncSec < time.Minute {
			policySyncSec = time.Minute
		}
	}

	var tlsCfg *tls.Config
	if cfg.MutualTLS || cfg.CACertPath != "" {
		t, err := LoadTLSConfig(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.CACertPath, cfg.MutualTLS)
		if err != nil {
			return nil, fmt.Errorf("control_plane: tls: %w", err)
		}
		tlsCfg = t
	}

	client, err := NewGRPCClient(cfg.ServerHost, cfg.GRPCPort, cfg.AgentID, tlsCfg, logger)
	if err != nil {
		return nil, err
	}

	cp := &ControlPlane{
		client:    client,
		logger:    logger,
		startTime: time.Now().UTC(),
		stopCh:    make(chan struct{}),
		rulesLoaded: func() int { return 0 },
		registerMeta: registrationMeta{
			agentID:  cfg.AgentID,
			hostname: cfg.Hostname,
			version:  cfg.Version,
			commit:   cfg.Commit,
		},
		reconnectSec: time.Duration(cfg.ReconnectSec) * time.Second,
		heartbeatSec: time.Duration(cfg.HeartbeatSec) * time.Second,
		policySyncSec: policySyncSec,
	}

	transport := &grpcHeartbeatTransport{
		client:  client,
		rulesFn: cp.rulesCount,
		onCommands: func(cmds []*protocol.Command) {
			cp.handleCommands(cmds...)
		},
	}
	cp.heartbeat = NewHeartbeat(cfg.AgentID, cfg.Version, cfg.Hostname, transport, logger)
	return cp, nil
}

func controlPlaneEnabled(cfg ControlPlaneConfig) bool {
	if cfg.AirGapMode {
		return false
	}
	return cfg.ServerHost != "" && cfg.GRPCPort > 0
}

func (cp *ControlPlane) rulesCount() int {
	if cp.rulesLoaded != nil {
		return cp.rulesLoaded()
	}
	return 0
}

// SetRulesLoaded sets a callback returning the number of loaded detection rules.
func (cp *ControlPlane) SetRulesLoaded(fn func() int) {
	if cp == nil {
		return
	}
	cp.rulesLoaded = fn
}

// SetCommandDispatch registers the handler for server commands.
func (cp *ControlPlane) SetCommandDispatch(fn CommandDispatch) {
	if cp == nil {
		return
	}
	cp.dispatch = fn
}

// Heartbeat returns the heartbeat reporter for counter updates.
func (cp *ControlPlane) Heartbeat() *Heartbeat {
	if cp == nil {
		return nil
	}
	return cp.heartbeat
}

// Connected reports whether the control plane has completed registration.
func (cp *ControlPlane) Connected() bool {
	if cp == nil {
		return false
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.connected
}

// Start connects, registers, and runs heartbeat plus event streaming.
func (cp *ControlPlane) Start(ctx context.Context) error {
	if cp == nil {
		return nil
	}
	if err := cp.client.Connect(ctx); err != nil {
		return fmt.Errorf("control_plane: connect: %w", err)
	}

	reg := &protocol.RegistrationRequest{
		AgentId:  cp.registerMeta.agentID,
		Hostname: cp.registerMeta.hostname,
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  cp.registerMeta.version,
		Commit:   cp.registerMeta.commit,
		Capabilities: []string{
			"telemetry_stream",
			"alert_report",
			"response_actions",
		},
	}
	resp, err := cp.client.Register(ctx, reg)
	if err != nil {
		return fmt.Errorf("control_plane: register: %w", err)
	}
	if resp != nil && !resp.GetAccepted() {
		return fmt.Errorf("control_plane: registration rejected: %s", resp.GetMessage())
	}

	cp.mu.Lock()
	cp.connected = true
	cp.mu.Unlock()

	interval := cp.heartbeatSec
	if resp != nil && resp.GetHeartbeatSec() > 0 {
		interval = time.Duration(resp.GetHeartbeatSec()) * time.Second
	}

	cp.client.SetCommandHandler(func(cmd *protocol.Command) {
		cp.handleCommands(cmd)
	})
	if err := cp.heartbeat.Start(ctx, interval); err != nil {
		cp.logger.Warn("control_plane heartbeat start", zap.Error(err))
	}

	go cp.streamLoop(ctx)
	go cp.policyLoop(ctx)
	cp.logger.Info("control_plane started",
		zap.String("server", cp.client.ServerAddr()),
		zap.String("agent_id", cp.client.AgentID()),
	)
	return nil
}

// Stop shuts down heartbeat and the gRPC client.
func (cp *ControlPlane) Stop() {
	if cp == nil {
		return
	}
	cp.stopOnce.Do(func() {
		close(cp.stopCh)
	})
	if cp.heartbeat != nil {
		cp.heartbeat.Stop()
	}
	if cp.client != nil {
		_ = cp.client.Close()
	}
	cp.mu.Lock()
	cp.connected = false
	cp.mu.Unlock()
}

// SendAlert transmits a high-priority alert to the control plane.
func (cp *ControlPlane) SendAlert(ctx context.Context, al schema.Alert, productVersion string) error {
	if cp == nil {
		return nil
	}
	if !cp.Connected() {
		return fmt.Errorf("control_plane: not connected")
	}
	ev := alertpkg.EventsFromSchema(al)
	return cp.client.SendAlert(ctx, ev, productVersion)
}

// SendEventsAlert transmits a pipeline alert to the control plane.
func (cp *ControlPlane) SendEventsAlert(ctx context.Context, alert *events.Alert, productVersion string) error {
	if cp == nil || !cp.Connected() || alert == nil {
		return nil
	}
	return cp.client.SendAlert(ctx, alert, productVersion)
}

func (cp *ControlPlane) streamLoop(ctx context.Context) {
	for {
		select {
		case <-cp.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		if err := cp.client.StreamEvents(ctx); err != nil && ctx.Err() == nil {
			cp.logger.Warn("control_plane stream ended", zap.Error(err))
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-cp.stopCh:
			return
		case <-ctx.Done():
			return
		case <-time.After(cp.reconnectSec):
		}
	}
}

func (cp *ControlPlane) handleCommands(cmds ...*protocol.Command) {
	if cp == nil || cp.dispatch == nil {
		return
	}
	for _, cmd := range cmds {
		if cmd == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := cp.dispatch(ctx, cmd); err != nil {
			cp.logger.Warn("control_plane command failed",
				zap.String("command_id", cmd.GetCommandId()),
				zap.Error(err),
			)
		}
		cancel()
	}
}
