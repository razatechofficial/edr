package response

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

type testExecutor struct{ lastOp string }

func (t *testExecutor) Execute(_ context.Context, op string, _ map[string]interface{}, _ detection.Detection) error {
	t.lastOp = op
	return nil
}

func TestSelectPB001_T1055_P1_085(t *testing.T) {
	t.Parallel()
	log := zap.NewNop()
	ex := &testExecutor{}
	dir := t.TempDir()
	p := filepath.Join(dir, "pb.yml")
	mustWrite(t, p, `playbooks:
  - id: "PB-001"
    name: "x"
    triggers:
      - technique: "T1055"
        min_severity: P1
        min_confidence: 0.8
    approval_required: false
    actions:
      - action: alert
        params: { channel: "soc" }
`)
	eng, err := NewPlaybookEngineFromFile(p, ex, &AutoApprovalGateway{}, "10.0.0.1", "/q", log)
	if err != nil {
		t.Fatal(err)
	}
	d := detection.Detection{
		TechniqueID: "T1055",
		Severity:    detection.P1,
		Confidence:  0.85,
	}
	pb := eng.selectPlaybook(d)
	if pb == nil || pb.ID != "PB-001" {
		t.Fatalf("got %+v", pb)
	}
}

func TestSelectPB002_T1486_P0_not_P2(t *testing.T) {
	t.Parallel()
	log := zap.NewNop()
	ex := &testExecutor{}
	dir := t.TempDir()
	p := filepath.Join(dir, "pb.yml")
	mustWrite(t, p, `playbooks:
  - id: "PB-002"
    name: "Ransom"
    triggers:
      - technique: "T1486"
        min_severity: P0
    approval_required: false
    actions:
      - action: alert
        params: {}
`)
	eng, err := NewPlaybookEngineFromFile(p, ex, &AutoApprovalGateway{}, "10.0.0.1", "/q", log)
	if err != nil {
		t.Fatal(err)
	}
	d0 := detection.Detection{TechniqueID: "T1486", Severity: detection.P0, Confidence: 1}
	if eng.selectPlaybook(d0) == nil {
		t.Fatal("P0 should match")
	}
	d2 := detection.Detection{TechniqueID: "T1486", Severity: detection.P2, Confidence: 1}
	if eng.selectPlaybook(d2) != nil {
		t.Fatal("P2 should not match P0 min")
	}
}

func TestPB006_Approval(t *testing.T) {
	t.Parallel()
	log := zap.NewNop()
	ex := &testExecutor{}
	dir := t.TempDir()
	p := filepath.Join(dir, "pb.yml")
	mustWrite(t, p, `playbooks:
  - id: "PB-006"
    name: "Analyst"
    triggers:
      - min_severity: P2
        max_confidence: 0.6
    approval_required: true
    actions:
      - action: alert
        params: {}
`)
	eng, err := NewPlaybookEngineFromFile(p, ex, &AutoApprovalGateway{}, "10.0.0.1", "/q", log)
	if err != nil {
		t.Fatal(err)
	}
	d := detection.Detection{Severity: detection.P2, Confidence: 0.5}
	if eng.selectPlaybook(d) == nil {
		t.Fatal("select")
	}
	// Auto approves
	_ = eng.Handle(context.Background(), d)
}

func TestTemplatePID(t *testing.T) {
	t.Parallel()
	log := zap.NewNop()
	ex := &testExecutor{}
	dir := t.TempDir()
	p := filepath.Join(dir, "pb.yml")
	mustWrite(t, p, `playbooks:
  - id: "T"
    name: "T"
    triggers: [{ technique: "T1" }]
    approval_required: false
    actions:
      - action: kill_process
        params:
          target: "{{detection.event.pid}}"
`)
	eng, err := NewPlaybookEngineFromFile(p, ex, &AutoApprovalGateway{}, "10.0.0.1", "/q", log)
	if err != nil {
		t.Fatal(err)
	}
	d := detection.Detection{TechniqueID: "T1", Event: &detection.EventPayload{Process: &schema.ProcessEvent{PID: 4242}}}
	_ = eng.Handle(context.Background(), d)
	// kill path exercised via default executor in integration; here we only ensure template resolution in resolveMap:
	act := PAction{Type: "kill_process", Params: map[string]interface{}{"target": "{{detection.event.pid}}"}}
	r := eng.resolveAction(act, d)
	if r.Params["target"] != "4242" {
		t.Fatalf("target = %q", r.Params["target"])
	}
}

func TestTemplateMissing(t *testing.T) {
	t.Parallel()
	log := zap.NewNop()
	eng := &PlaybookEngine{agentIP: "1.1.1.1", quarDir: "/q", logger: log}
	d := detection.Detection{Event: nil}
	s := eng.subst("x{{detection.event.missing}}y", d)
	if s != "xy" {
		t.Fatalf("got %q", s)
	}
}

func TestMatchTrigger_SigmaAndBehavioral(t *testing.T) {
	t.Parallel()
	sigmaTr := &Trigger{Technique: "T1001", MinSeverity: "P1", Source: "sigma"}
	sigmaDet := detection.Detection{TechniqueID: "T1001", Severity: detection.P1, Source: detection.SourceSigma}
	if !matchTrigger(sigmaTr, sigmaDet) {
		t.Fatal("expected sigma trigger to match sigma detection")
	}
	if matchTrigger(sigmaTr, detection.Detection{TechniqueID: "T1001", Severity: detection.P1, Source: detection.SourceYARA}) {
		t.Fatal("sigma trigger must not match YARA-sourced detection")
	}
	behTr := &Trigger{Technique: "T1002", MinSeverity: "P1", Source: "behavioral"}
	behDet := detection.Detection{TechniqueID: "T1002", Severity: detection.P1, Source: detection.SourceBehavioral}
	if !matchTrigger(behTr, behDet) {
		t.Fatal("expected behavioral trigger to match behavioral detection")
	}
	if matchTrigger(behTr, detection.Detection{TechniqueID: "T1002", Severity: detection.P1, Source: detection.SourceSigma}) {
		t.Fatal("behavioral trigger must not match sigma-sourced detection")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
