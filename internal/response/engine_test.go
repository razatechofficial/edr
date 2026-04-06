package response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

type mockHandler struct {
	execFn     func(ctx context.Context, params map[string]interface{}) (*StepResult, error)
	rollbackFn func(ctx context.Context, params map[string]interface{}) error
	rollbacks  int
}

func (m *mockHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	if m.execFn != nil {
		return m.execFn(ctx, params)
	}
	return okResult(ActionKillProcess, "mock ok"), nil
}

func (m *mockHandler) Rollback(ctx context.Context, params map[string]interface{}) error {
	m.rollbacks++
	if m.rollbackFn != nil {
		return m.rollbackFn(ctx, params)
	}
	return nil
}

func newTestEngine(t *testing.T) *ResponseEngine {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	engine, err := NewResponseEngine(logger, auditPath)
	if err != nil {
		t.Fatalf("NewResponseEngine: %v", err)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

func TestResponseEngineExecute(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t)

	handler := &mockHandler{
		execFn: func(_ context.Context, params map[string]interface{}) (*StepResult, error) {
			return &StepResult{Success: true, Message: "process killed"}, nil
		},
	}
	engine.RegisterHandler(ActionKillProcess, handler)

	result, err := engine.Execute(context.Background(), ActionKillProcess, map[string]interface{}{"pid": 1234})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Success {
		t.Error("Success = false, want true")
	}
	if result.Action != ActionKillProcess {
		t.Errorf("Action = %q, want %q", result.Action, ActionKillProcess)
	}
}

func TestResponseEnginePlaybookRollback(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t)

	step1Handler := &mockHandler{}
	step2Handler := &mockHandler{}
	failHandler := &mockHandler{
		execFn: func(_ context.Context, _ map[string]interface{}) (*StepResult, error) {
			return failResult(ActionNetworkIsolate, "failed"), fmt.Errorf("network error")
		},
	}

	engine.RegisterHandler(ActionKillProcess, step1Handler)
	engine.RegisterHandler(ActionQuarantineFile, step2Handler)
	engine.RegisterHandler(ActionNetworkIsolate, failHandler)

	pb := &testPlaybook{
		name: "rollback-test",
		steps: []PlaybookStep{
			{Name: "step1", Action: ActionKillProcess, Required: true,
				Params: func(_ *events.Alert) map[string]interface{} { return map[string]interface{}{"pid": 1} }},
			{Name: "step2", Action: ActionQuarantineFile, Required: true,
				Params: func(_ *events.Alert) map[string]interface{} { return map[string]interface{}{"path": "/tmp/x"} }},
			{Name: "step3-fails", Action: ActionNetworkIsolate, Required: true,
				Params: func(_ *events.Alert) map[string]interface{} { return map[string]interface{}{} }},
		},
	}

	alert := &events.Alert{ID: "test-alert-001"}
	_, err := engine.ExecutePlaybook(context.Background(), pb, alert)
	if err == nil {
		t.Fatal("expected error from failing step 3")
	}

	if step1Handler.rollbacks != 1 {
		t.Errorf("step1 rollbacks = %d, want 1", step1Handler.rollbacks)
	}
	if step2Handler.rollbacks != 1 {
		t.Errorf("step2 rollbacks = %d, want 1", step2Handler.rollbacks)
	}
}

func TestAuditLoggerWritesEntry(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	if err := al.Log(AuditEntry{
		Action:  ActionKillProcess,
		Success: true,
		Message: "test entry",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("Unmarshal audit entry: %v", err)
	}
	if entry.Action != ActionKillProcess {
		t.Errorf("Action = %q, want %q", entry.Action, ActionKillProcess)
	}
	if !entry.Success {
		t.Error("Success = false, want true")
	}
}

type testPlaybook struct {
	name  string
	steps []PlaybookStep
}

func (p *testPlaybook) Name() string               { return p.name }
func (p *testPlaybook) Description() string         { return "test playbook" }
func (p *testPlaybook) Steps() []PlaybookStep       { return p.steps }
