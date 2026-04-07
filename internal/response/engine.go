package response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/events"
)

// Action represents a response action type that can be executed by the engine.
type Action string

const (
	ActionKillProcess      Action = "kill_process"
	ActionSuspendProcess   Action = "suspend_process"
	ActionQuarantineFile   Action = "quarantine_file"
	ActionNetworkIsolate   Action = "network_isolate"
	ActionNetworkRelease   Action = "network_release"
	ActionBlockHash        Action = "block_hash"
	ActionMemoryDump       Action = "memory_dump"
	ActionSnapshot         Action = "snapshot"
	ActionCollectForensics Action = "collect_forensics"
	ActionRegistryDelete   Action = "registry_delete"
	ActionRegistryRestore  Action = "registry_restore"
)

// StepResult records the outcome of a single playbook step, including timing
// and whether a rollback is available.
type StepResult struct {
	Action    Action        `json:"action"`
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
	Action   Action
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

// ResponseEngine orchestrates response actions and playbooks, dispatching each
// action to its registered handler and maintaining an append-only audit log.
type ResponseEngine struct {
	actions  map[Action]ActionHandler
	logger   *zap.Logger
	auditLog *AuditLogger
	mu       sync.RWMutex
}

// NewResponseEngine creates a ResponseEngine with the given logger and audit
// log path. Pass an empty auditPath to use the default /var/log/edr/audit.jsonl.
func NewResponseEngine(logger *zap.Logger, auditPath string) (*ResponseEngine, error) {
	if auditPath == "" {
		auditPath = "/var/log/edr/audit.jsonl"
	}
	al, err := NewAuditLogger(auditPath)
	if err != nil {
		return nil, fmt.Errorf("response engine: open audit log: %w", err)
	}

	e := &ResponseEngine{
		actions:  make(map[Action]ActionHandler),
		logger:   logger,
		auditLog: al,
	}
	return e, nil
}

// RegisterHandler binds an ActionHandler to the given action type. It is safe
// to call concurrently, but duplicate registrations overwrite silently.
func (e *ResponseEngine) RegisterHandler(action Action, handler ActionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actions[action] = handler
}

// Execute runs a single response action, logs the result, and returns the step outcome.
func (e *ResponseEngine) Execute(ctx context.Context, action Action, params map[string]interface{}) (*StepResult, error) {
	if requiresExplicitApproval(params) && !isApproved(params) {
		msg := "action blocked: explicit approval required"
		result := &StepResult{
			Action:    action,
			Success:   false,
			Message:   msg,
			Timestamp: time.Now(),
			Params:    params,
		}
		_ = e.auditLog.Log(AuditEntry{
			Timestamp: time.Now(),
			Action:    action,
			Params:    params,
			Success:   false,
			Message:   msg,
			Operator:  "engine",
		})
		return result, fmt.Errorf("response engine: %s", msg)
	}

	e.mu.RLock()
	handler, ok := e.actions[action]
	e.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("response engine: no handler registered for action %q", action)
	}

	start := time.Now()
	result, err := handler.Execute(ctx, params)
	elapsed := time.Since(start)

	if result == nil {
		result = &StepResult{
			Action:    action,
			Timestamp: start,
			Duration:  elapsed,
		}
	} else {
		result.Duration = elapsed
		result.Timestamp = start
	}
	result.Action = action
	result.Params = params

	entry := AuditEntry{
		Timestamp: start,
		Action:    action,
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
			zap.String("action", string(action)),
			zap.Error(err),
			zap.Duration("elapsed", elapsed),
		)
		return result, fmt.Errorf("response engine: execute %s: %w", action, err)
	}

	e.logger.Info("action executed",
		zap.String("action", string(action)),
		zap.Bool("success", result.Success),
		zap.Duration("elapsed", elapsed),
	)
	return result, nil
}

// ExecutePlaybook runs every step of the playbook in order. If a required step
// fails, all previously succeeded steps are rolled back in reverse order and
// the partial results are returned alongside the error.
func (e *ResponseEngine) ExecutePlaybook(ctx context.Context, pb Playbook, alert *events.Alert) ([]*StepResult, error) {
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
func (e *ResponseEngine) rollbackCompleted(ctx context.Context, steps []PlaybookStep, results []*StepResult, alert *events.Alert) {
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
			Action:    Action(fmt.Sprintf("rollback_%s", step.Action)),
			Params:    params,
			Success:   true,
			Message:   fmt.Sprintf("rolled back step %q", step.Name),
			Operator:  "engine",
		})
	}
}

// Close releases resources held by the engine (audit log file handles, etc.).
func (e *ResponseEngine) Close() error {
	return e.auditLog.Close()
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

// AuditEntry records a single auditable event for compliance and forensic review.
type AuditEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	Action       Action                 `json:"action"`
	Params       map[string]interface{} `json:"params,omitempty"`
	Success      bool                   `json:"success"`
	Message      string                 `json:"message"`
	Duration     time.Duration          `json:"duration_ns,omitempty"`
	AlertID      string                 `json:"alert_id,omitempty"`
	PlaybookName string                 `json:"playbook_name,omitempty"`
	Operator     string                 `json:"operator"`
}

// AuditLogger writes append-only JSON-lines audit records.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
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
	return &AuditLogger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// Log appends a single audit entry atomically.
func (a *AuditLogger) Log(entry AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(entry); err != nil {
		return fmt.Errorf("audit logger: encode: %w", err)
	}
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
