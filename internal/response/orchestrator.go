package response

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/forensics"
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
	ForensicsDeep forensics.ForensicsDeepConfig
}

// ApprovalConfig mirrors agent YAML.
type ApprovalConfig struct {
	Mode               string
	WebhookURL         string
	CallbackURL        string
	CallbackListenAddr string
	// CallbackToken authenticates callers of /approve and /reject. Without it
	// the callback server does not start.
	CallbackToken string
	ApprovalDir   string
	TimeoutSec    int
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
	// callbackSrv serves GET /approve/{id} and /reject/{id} for webhook approval mode.
	callbackSrv   *http.Server
	callbackAddr  string
	callbackToken string
	approvalMode  string

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
	sl := &standardLayer{
		rm:            NewRollbackManager(),
		logger:        cfg.Logger,
		cmap:          make(map[string]Containment),
		callbackAddr:  strings.TrimSpace(cfg.Approval.CallbackListenAddr),
		callbackToken: strings.TrimSpace(cfg.Approval.CallbackToken),
		approvalMode:  strings.TrimSpace(strings.ToLower(cfg.Approval.Mode)),
	}
	exec := &DefaultActionExecutor{
		Eng:                 cfg.ActionEng,
		Logger:              cfg.Logger,
		ForensicsDir:        cfg.ForensicsDir,
		QuarantineDir:       cfg.QuarantineDir,
		HostID:              cfg.HostID,
		AgentIP:             cfg.AgentIP,
		ForensicsDeep:       cfg.ForensicsDeep,
		RegisterContainment: sl.RegisterContainment,
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
	sl.pb = pb
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
	case "auto":
		return &AutoApprovalGateway{}
	default:
		// Unset or unrecognised. Refuse rather than approve: an unconfigured
		// deployment should not silently sanction destructive actions.
		return &DenyApprovalGateway{Logger: log}
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
	if s.approvalMode == "webhook" && s.callbackAddr != "" {
		s.startApprovalCallback()
	}
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
	if s.callbackSrv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.callbackSrv.Shutdown(shutCtx)
		cancel()
		s.callbackSrv = nil
	}
	if s.rollStop != nil {
		s.rollStop()
	}
	s.mu.Unlock()
}

// startApprovalCallback serves POST /approve/{id} and /reject/{id} and calls
// [SubmitApprovalResult].
//
// Approving a pending playbook authorises a destructive action, so the endpoint
// is a credential-protected control surface rather than a convenience:
//
//   - It refuses to start without a shared token. An endpoint that approves on
//     a bare request only needs an attacker to reach the port and learn an id,
//     and the id travels in a webhook that may itself be logged or proxied.
//   - It is POST, not GET. A GET is reachable from a browser on the host by a
//     page the operator merely visits, and is retried and prefetched by things
//     that have no business approving anything.
//   - The token is compared in constant time, because a timing oracle on an
//     approval token is as good as the token.
func (s *standardLayer) startApprovalCallback() {
	if s.logger == nil {
		s.logger = zap.NewNop()
	}
	token := strings.TrimSpace(s.callbackToken)
	if token == "" {
		s.logger.Error("approval callback not started: no callback_token configured",
			zap.String("addr", s.callbackAddr),
			zap.String("remedy", "set response.approval.callback_token, or clear callback_listen_addr"),
		)
		return
	}
	mux := http.NewServeMux()
	writeOK := func(w http.ResponseWriter, r *http.Request, id string, approved bool) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		presented := r.Header.Get("X-EDR-Approval-Token")
		if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			s.logger.Warn("approval callback rejected: bad token",
				zap.String("path", r.URL.Path),
				zap.String("remote", r.RemoteAddr),
			)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing id\n"))
			return
		}
		SubmitApprovalResult(id, approved)
		if s.logger != nil {
			s.logger.Info("approval callback", zap.String("id", id), zap.Bool("approved", approved), zap.String("path", r.URL.Path))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
	mux.HandleFunc("/approve/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/approve/"), "/")
		writeOK(w, r, id, true)
	})
	mux.HandleFunc("/reject/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/reject/"), "/")
		writeOK(w, r, id, false)
	})
	srv := &http.Server{Addr: s.callbackAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	s.mu.Lock()
	s.callbackSrv = srv
	s.mu.Unlock()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if s.logger != nil {
				s.logger.Error("approval callback server failed", zap.Error(err), zap.String("addr", s.callbackAddr))
			}
		}
	}()
}
