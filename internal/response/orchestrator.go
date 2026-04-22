package response

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/razatechofficial/edr/internal/detection"
	"go.uber.org/zap"
)

// EngineConfig configures the YAML response layer.
type EngineConfig struct {
	PlaybooksPath string
	ForensicsDir  string
	QuarantineDir string
	AgentIP       string
	HostID        string
	Logger        *zap.Logger
	Approval      ApprovalConfig
	ActionEng     *ActionEngine
}

// ApprovalConfig mirrors agent YAML.
type ApprovalConfig struct {
	Mode        string
	WebhookURL  string
	CallbackURL string
	ApprovalDir string
	TimeoutSec  int
}

// standardLayer implements [ResponseEngine].
type standardLayer struct {
	pb       *PlaybookEngine
	rm       *RollbackManager
	logger   *zap.Logger
	mu       sync.RWMutex
	cmap     map[string]Containment
	rollCtx  context.Context
	rollStop context.CancelFunc

	actionsExec         atomic.Uint64
	actionsOK           atomic.Uint64
	actionsFail         atomic.Uint64
	forensicCollections atomic.Uint64
}

// NewEngine builds a [ResponseEngine] from config (playbooks file + executor + approval).
func NewEngine(cfg EngineConfig) (ResponseEngine, error) {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.HostID == "" {
		cfg.HostID = "local"
	}
	if cfg.AgentIP == "" {
		cfg.AgentIP = "127.0.0.1"
	}
	exec := &DefaultActionExecutor{
		Eng:           cfg.ActionEng,
		Logger:        cfg.Logger,
		ForensicsDir:  cfg.ForensicsDir,
		QuarantineDir: cfg.QuarantineDir,
		HostID:        cfg.HostID,
		AgentIP:       cfg.AgentIP,
	}
	gw := buildApprovalGateway(cfg.Approval, cfg.Logger)
	pbPath := cfg.PlaybooksPath
	if pbPath == "" {
		return nil, fmt.Errorf("playbooks path required")
	}
	pb, err := NewPlaybookEngineFromFile(pbPath, exec, gw, cfg.AgentIP, cfg.QuarantineDir, cfg.Logger)
	if err != nil {
		return nil, err
	}
	sl := &standardLayer{
		pb:     pb,
		rm:     NewRollbackManager(),
		logger: cfg.Logger,
		cmap:   make(map[string]Containment),
	}
	exec.OnForensic = func() { sl.forensicCollections.Add(1) }
	return sl, nil
}

func buildApprovalGateway(ac ApprovalConfig, log *zap.Logger) ApprovalGateway {
	switch ac.Mode {
	case "webhook":
		return &WebhookApprovalGateway{
			WebhookURL:  ac.WebhookURL,
			CallbackURL: ac.CallbackURL,
			TimeoutSec:  ac.TimeoutSec,
			Logger:      log,
		}
	case "file":
		return &FileApprovalGateway{ApprovalDir: ac.ApprovalDir}
	default:
		return &AutoApprovalGateway{}
	}
}

// Start begins background workers (rollback timer).
func (s *standardLayer) Start(ctx context.Context) {
	s.mu.Lock()
	if s.rollStop != nil {
		s.mu.Unlock()
		return
	}
	s.rollCtx, s.rollStop = context.WithCancel(ctx)
	s.mu.Unlock()
	go s.rm.AutoRollbackLoop(s.rollCtx)
}

// Handle runs the playbook engine for a detection.
func (s *standardLayer) Handle(ctx context.Context, d detection.Detection) error {
	s.actionsExec.Add(1)
	if err := s.pb.Handle(ctx, d); err != nil {
		s.actionsFail.Add(1)
		return err
	}
	s.actionsOK.Add(1)
	return nil
}

// ActiveContainments returns a snapshot of tracked containments.
func (s *standardLayer) ActiveContainments() []Containment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Containment, 0, len(s.cmap))
	for _, c := range s.cmap {
		if c.Status == ContainmentActive {
			out = append(out, c)
		}
	}
	return out
}

// Release runs rollback for a containment id.
func (s *standardLayer) Release(containmentID string) error {
	s.mu.RLock()
	c, ok := s.cmap[containmentID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown containment %s", containmentID)
	}
	if c.RollbackFn == nil {
		return fmt.Errorf("action not reversible: no rollback for %s", containmentID)
	}
	if err := c.RollbackFn(context.Background()); err != nil {
		return err
	}
	s.mu.Lock()
	c.Status = ContainmentReleased
	s.cmap[containmentID] = c
	s.mu.Unlock()
	return nil
}

// RegisterContainment is used by tests and future action wiring to track reversibility.
func (s *standardLayer) RegisterContainment(c Containment) {
	s.mu.Lock()
	s.cmap[c.ID] = c
	s.rm.Register(c, c.RollbackFn)
	s.mu.Unlock()
}

// Stats returns aggregate stats.
func (s *standardLayer) Stats() ResponseStats {
	s.mu.RLock()
	active := 0
	for _, c := range s.cmap {
		if c.Status == ContainmentActive {
			active++
		}
	}
	s.mu.RUnlock()
	return ResponseStats{
		ActionsExecuted:     s.actionsExec.Load(),
		ActionsSucceeded:    s.actionsOK.Load(),
		ActionsFailed:       s.actionsFail.Load(),
		ActiveContainments:  active,
		ForensicCollections: s.forensicCollections.Load(),
	}
}

// Stop cancels background workers (optional; not in interface).
func (s *standardLayer) Stop() {
	s.mu.Lock()
	if s.rollStop != nil {
		s.rollStop()
	}
	s.mu.Unlock()
}
