package rules

import (
	"testing"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/ocsf"
)

func TestActivationFromMapOCSF(t *testing.T) {
	t.Parallel()
	act := activationFromMap(map[string]interface{}{
		"event_type":        "process",
		"process.file.name": "cmd.exe",
		"process.file.path": "C:\\Windows\\System32\\cmd.exe",
		"class_uid":         float64(1007),
		"destination.port":  float64(443),
	})
	if act["process_file_name"] != "cmd.exe" {
		t.Fatalf("process_file_name=%v", act["process_file_name"])
	}
	if act["class_uid"] != int64(1007) {
		t.Fatalf("class_uid=%v", act["class_uid"])
	}
	if act["destination_port"] != int64(443) {
		t.Fatalf("destination_port=%v", act["destination_port"])
	}
}

func TestCustomEngineOCSFNativeRule(t *testing.T) {
	t.Parallel()
	e, err := NewCustomEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	rule := CustomRule{
		ID:         "OCSF-TEST-001",
		Name:       "OCSF process match",
		Severity:   "high",
		Enabled:    true,
		Expression: `class_uid == 1007 && process_cmd_line.contains("-enc")`,
	}
	if err := e.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	alerts := e.Evaluate(EventToMap(map[string]interface{}{
		"event_type":   "process",
		"process_name": "powershell.exe",
		"command_line": "powershell -enc ABC",
	}))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
}

func TestCustomEngineNestedOCSFRule(t *testing.T) {
	t.Parallel()
	e, err := NewCustomEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	rule := CustomRule{
		ID:         "OCSF-TEST-002",
		Name:       "Nested OCSF map",
		Severity:   "medium",
		Enabled:    true,
		Expression: `ocsf.class_uid == 1007 && ocsf.process.cmd_line.contains("whoami")`,
	}
	if err := e.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	ev := EventToMap(map[string]interface{}{
		"event_type":   "process",
		"command_line": "cmd /c whoami",
	})
	if ev["ocsf"] == nil {
		t.Fatal("expected nested ocsf on event map")
	}
	alerts := e.Evaluate(ev)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	_ = ocsf.ClassUIDProcessActivity
}
