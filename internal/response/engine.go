package response

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/pkg/events"
)

// OpKey is a string identifier for a response operation registered on [ActionEngine].
type OpKey string

const (
	OpKillProcess      OpKey = "kill_process"
	OpSuspendProcess   OpKey = "suspend_process"
	OpQuarantineFile   OpKey = "quarantine_file"
	OpNetworkIsolate   OpKey = "network_isolate"
	OpNetworkRelease   OpKey = "network_release"
	OpBlockHash        OpKey = "block_hash"
	OpMemoryDump       OpKey = "memory_dump"
	OpSnapshot         OpKey = "snapshot"
	OpCollectForensics OpKey = "collect_forensics"
	OpRegistryDelete   OpKey = "registry_delete"
	OpRegistryRestore  OpKey = "registry_restore"
)

// StepResult records the outcome of a single playbook step, including timing
// and whether a rollback is available.
type StepResult struct {
	Action    OpKey         `json:"action"`
	StepName  string        `json:"step_name"`
	Success   bool          `json:"success"`
	Message   string        `json:"message"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	Params    map[string]interface{}
}

// PlaybookStep defines a single step within a Playbook sequence.
type PlaybookStep struct {
	Name     string
	Action   OpKey
	Params   func(alert *events.Alert) map[string]interface{}
	Required bool // if true, failure aborts the playbook and triggers rollback
}

// Playbook defines an automated response sequence that the engine can execute
// as an atomic unit with rollback semantics.
type Playbook interface {
	Name() string
	Description() string
	Steps() []PlaybookStep
}

// ActionHandler executes a specific response action and can undo it on rollback.
type ActionHandler interface {
	Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error)
	Rollback(ctx context.Context, params map[string]interface{}) error
}

// ActionEngine dispatches registered [OpKey] handlers and maintains an audit log.
type ActionEngine struct {
	actions  map[OpKey]ActionHandler
	logger   *zap.Logger
	auditLog *AuditLogger
	mu       sync.RWMutex
}

// NewActionEngine creates an ActionEngine with the given logger and audit log path.
// Pass an empty auditPath to use the default /var/log/edr/audit.jsonl.
func NewActionEngine(logger *zap.Logger, auditPath string) (*ActionEngine, error) {
	if auditPath == "" {
		auditPath = "/var/log/edr/audit.jsonl"
	}
	al, err := NewAuditLogger(auditPath)
	if err != nil {
		return nil, fmt.Errorf("response engine: open audit log: %w", err)
	}

	e := &ActionEngine{
		actions:  make(map[OpKey]ActionHandler),
		logger:   logger,
		auditLog: al,
	}
	return e, nil
}

// NewResponseEngine returns a new [ActionEngine] (name kept for call-site compatibility).
func NewResponseEngine(logger *zap.Logger, auditPath string) (*ActionEngine, error) {
	return NewActionEngine(logger, auditPath)
}

// RegisterHandler binds an ActionHandler to the given operation. Duplicate
// registrations overwrite silently.
func (e *ActionEngine) RegisterHandler(key OpKey, handler ActionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actions[key] = handler
}

// Execute runs a single response action, logs the result, and returns the step outcome.
func (e *ActionEngine) Execute(ctx context.Context, key OpKey, params map[string]interface{}) (*StepResult, error) {
	if requiresExplicitApproval(params) && !isApproved(params) {
		msg := "action blocked: explicit approval required"
		result := &StepResult{
			Action:    key,
			Success:   false,
			Message:   msg,
			Timestamp: time.Now(),
			Params:    params,
		}
		_ = e.auditLog.Log(AuditEntry{
			Timestamp: time.Now(),
			Action:    string(key),
			Params:    params,
			Success:   false,
			Message:   msg,
			Operator:  "engine",
		})
		return result, fmt.Errorf("response engine: %s", msg)
	}

	e.mu.RLock()
	handler, ok := e.actions[key]
	e.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("response engine: no handler registered for action %q", key)
	}

	start := time.Now()
	result, err := handler.Execute(ctx, params)
	elapsed := time.Since(start)

	if result == nil {
		result = &StepResult{
			Action:    key,
			Timestamp: start,
			Duration:  elapsed,
		}
	} else {
		result.Duration = elapsed
		result.Timestamp = start
	}
	result.Action = key
	result.Params = params

	entry := AuditEntry{
		Timestamp: start,
		Action:    string(key),
		Params:    params,
		Success:   result.Success,
		Message:   result.Message,
		Duration:  elapsed,
		Operator:  "engine",
	}

	if logErr := e.auditLog.Log(entry); logErr != nil {
		e.logger.Error("failed to write audit entry", zap.Error(logErr))
	}

	if err != nil {
		e.logger.Error("action failed",
			zap.String("action", string(key)),
			zap.Error(err),
			zap.Duration("elapsed", elapsed),
		)
		return result, fmt.Errorf("response engine: execute %s: %w", key, err)
	}

	e.logger.Info("action executed",
		zap.String("action", string(key)),
		zap.Bool("success", result.Success),
		zap.Duration("elapsed", elapsed),
	)
	return result, nil
}

// ExecutePlaybook runs every step of the playbook in order. If a required step
// fails, all previously succeeded steps are rolled back in reverse order and
// the partial results are returned alongside the error.
func (e *ActionEngine) ExecutePlaybook(ctx context.Context, pb Playbook, alert *events.Alert) ([]*StepResult, error) {
	steps := pb.Steps()
	results := make([]*StepResult, 0, len(steps))

	e.logger.Info("playbook started",
		zap.String("playbook", pb.Name()),
		zap.String("alert_id", alert.ID),
		zap.Int("steps", len(steps)),
	)

	if err := e.auditLog.Log(AuditEntry{
		Timestamp:    time.Now(),
		Action:       "playbook_start",
		PlaybookName: pb.Name(),
		AlertID:      alert.ID,
		Success:      true,
		Message:      fmt.Sprintf("starting playbook %q with %d steps", pb.Name(), len(steps)),
		Operator:     "engine",
	}); err != nil {
		e.logger.Error("audit log write failed", zap.Error(err))
	}

	for i, step := range steps {
		select {
		case <-ctx.Done():
			e.rollbackCompleted(ctx, steps[:i], results, alert)
			return results, fmt.Errorf("response engine: playbook %q cancelled at step %d/%d: %w",
				pb.Name(), i+1, len(steps), ctx.Err())
		default:
		}

		params := step.Params(alert)
		e.logger.Info("executing playbook step",
			zap.String("playbook", pb.Name()),
			zap.Int("step", i+1),
			zap.String("step_name", step.Name),
			zap.String("action", string(step.Action)),
		)

		result, err := e.Execute(ctx, step.Action, params)
		if result != nil {
			result.StepName = step.Name
		}
		results = append(results, result)

		if err != nil || (result != nil && !result.Success) {
			if step.Required {
				e.logger.Error("required step failed, rolling back",
					zap.String("playbook", pb.Name()),
					zap.String("step", step.Name),
					zap.Error(err),
				)
				e.rollbackCompleted(ctx, steps[:i], results[:i], alert)
				return results, fmt.Errorf("response engine: playbook %q failed at required step %q: %w",
					pb.Name(), step.Name, err)
			}
			e.logger.Warn("optional step failed, continuing",
				zap.String("playbook", pb.Name()),
				zap.String("step", step.Name),
				zap.Error(err),
			)
		}
	}

	if err := e.auditLog.Log(AuditEntry{
		Timestamp:    time.Now(),
		Action:       "playbook_complete",
		PlaybookName: pb.Name(),
		AlertID:      alert.ID,
		Success:      true,
		Message:      fmt.Sprintf("playbook %q completed all %d steps", pb.Name(), len(steps)),
		Operator:     "engine",
	}); err != nil {
		e.logger.Error("audit log write failed", zap.Error(err))
	}

	e.logger.Info("playbook completed",
		zap.String("playbook", pb.Name()),
		zap.String("alert_id", alert.ID),
	)
	return results, nil
}

// rollbackCompleted reverses all previously executed steps in reverse order.
func (e *ActionEngine) rollbackCompleted(ctx context.Context, steps []PlaybookStep, results []*StepResult, alert *events.Alert) {
	for i := len(results) - 1; i >= 0; i-- {
		if results[i] == nil || !results[i].Success {
			continue
		}
		step := steps[i]
		e.mu.RLock()
		handler, ok := e.actions[step.Action]
		e.mu.RUnlock()
		if !ok {
			continue
		}

		params := step.Params(alert)
		e.logger.Info("rolling back step",
			zap.String("step", step.Name),
			zap.String("action", string(step.Action)),
		)
		if err := handler.Rollback(ctx, params); err != nil {
			e.logger.Error("rollback failed",
				zap.String("step", step.Name),
				zap.Error(err),
			)
		}

		_ = e.auditLog.Log(AuditEntry{
			Timestamp: time.Now(),
			Action:    fmt.Sprintf("rollback_%s", string(step.Action)),
			Params:    params,
			Success:   true,
			Message:   fmt.Sprintf("rolled back step %q", step.Name),
			Operator:  "engine",
		})
	}
}

// Close releases resources held by the engine (audit log file handles, etc.).
func (e *ActionEngine) Close() error {
	return e.auditLog.Close()
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

// AuditEntry records a single auditable event for compliance and forensic review.
type AuditEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	Action       string                 `json:"action"`
	Params       map[string]interface{} `json:"params,omitempty"`
	Success      bool                   `json:"success"`
	Message      string                 `json:"message"`
	Duration     time.Duration          `json:"duration_ns,omitempty"`
	AlertID      string                 `json:"alert_id,omitempty"`
	PlaybookName string                 `json:"playbook_name,omitempty"`
	Operator     string                 `json:"operator"`
	PrevHash     string                 `json:"prev_hash,omitempty"`
	EntryHash    string                 `json:"entry_hash,omitempty"`
	Signature    string                 `json:"signature,omitempty"`
}

// AuditLogger writes append-only JSON-lines audit records.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
	prev []byte
	key  []byte
}

// NewAuditLogger opens (or creates) the audit log file in append-only mode.
func NewAuditLogger(path string) (*AuditLogger, error) {
	if err := os.MkdirAll(pathDir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit logger: create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit logger: open file: %w", err)
	}
	key := []byte(os.Getenv("EDR_AUDIT_SIGNING_KEY"))
	if len(key) == 0 {
		hostname, _ := os.Hostname()
		derived := sha256.Sum256([]byte("edr-audit-" + hostname + "-" + path))
		key = derived[:]
	}
	return &AuditLogger{
		file: f,
		enc:  json.NewEncoder(f),
		key:  key,
	}, nil
}

// Log appends a single audit entry atomically.
func (a *AuditLogger) Log(entry AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	prevHex := hex.EncodeToString(a.prev)
	entry.PrevHash = prevHex
	sum := entryDigest(entry)
	entry.EntryHash = hex.EncodeToString(sum[:])
	if len(a.key) > 0 {
		mac := hmac.New(sha256.New, a.key)
		mac.Write(sum[:])
		entry.Signature = hex.EncodeToString(mac.Sum(nil))
	}
	if err := a.enc.Encode(entry); err != nil {
		return fmt.Errorf("audit logger: encode: %w", err)
	}
	a.prev = sum[:]
	return a.file.Sync()
}

// Close flushes and closes the underlying file.
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// pathDir returns the directory component of a file path.
func pathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}

func requiresExplicitApproval(params map[string]interface{}) bool {
	if params == nil {
		return false
	}
	v, ok := params["requires_approval"]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func isApproved(params map[string]interface{}) bool {
	if params == nil {
		return false
	}
	v, ok := params["approved"]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func entryDigest(entry AuditEntry) [32]byte {
	type digestEntry struct {
		Timestamp    time.Time              `json:"timestamp"`
		Action       string                 `json:"action"`
		Params       map[string]interface{} `json:"params,omitempty"`
		Success      bool                   `json:"success"`
		Message      string                 `json:"message"`
		Duration     time.Duration          `json:"duration_ns,omitempty"`
		AlertID      string                 `json:"alert_id,omitempty"`
		PlaybookName string                 `json:"playbook_name,omitempty"`
		Operator     string                 `json:"operator"`
		PrevHash     string                 `json:"prev_hash,omitempty"`
	}
	b, _ := json.Marshal(digestEntry{
		Timestamp:    entry.Timestamp,
		Action:       entry.Action,
		Params:       entry.Params,
		Success:      entry.Success,
		Message:      entry.Message,
		Duration:     entry.Duration,
		AlertID:      entry.AlertID,
		PlaybookName: entry.PlaybookName,
		Operator:     entry.Operator,
		PrevHash:     entry.PrevHash,
	})
	return sha256.Sum256(b)
}

// ---------------------------------------------------------------------------
// Response pipeline types ([ResponseEngine], containments, stats)
// ---------------------------------------------------------------------------

// ResponseEngine is the high-level automated response interface (playbooks, containments, stats).
// The legacy [ActionEngine] executes registered [OpKey] handlers; this type orchestrates on top of it.
type ResponseEngine interface {
	Handle(ctx context.Context, d detection.Detection) error
	ActiveContainments() []Containment
	Release(containmentID string) error
	Stats() ResponseStats
	Start(ctx context.Context)
}

// Action is the semantic action type for containments and statistics (int enum per product spec).
type Action int

const (
	ActionKillProcess Action = iota
	ActionNetworkIsolate
	ActionNetworkBlock
	ActionFileQuarantine
	ActionFileDelete
	ActionUserDisable
	ActionMemoryDump
	ActionProcessDump
	ActionSnapshotCreate
	ActionCollectForensics
	ActionAlert
	ActionCustomScript
)

// Containment records an active or completed response action with optional rollback.
type Containment struct {
	ID         string
	HostID     string
	Action     Action
	Target     string
	AppliedAt  time.Time
	ExpiresAt  time.Time
	Detection  detection.Detection
	ApprovedBy string
	Status     ContainmentStatus
	RollbackFn func(ctx context.Context) error
}

// ContainmentStatus is the lifecycle of a containment record.
type ContainmentStatus int

const (
	ContainmentActive ContainmentStatus = iota
	ContainmentReleased
	ContainmentFailed
	ContainmentExpired
)

// ResponseStats are aggregate response metrics.
type ResponseStats struct {
	ActionsExecuted     uint64
	ActionsSucceeded    uint64
	ActionsFailed       uint64
	ActiveContainments  int
	ForensicCollections uint64
}
