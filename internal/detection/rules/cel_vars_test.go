package rules

import (
	"testing"

	"go.uber.org/zap"
)

func TestActivationFromMapOCSF(t *testing.T) {
	t.Parallel()
	act := activationFromMap(map[string]interface{}{
		"event_type":           "process",
		"process.file.name":    "cmd.exe",
		"process.file.path":    "C:\\Windows\\System32\\cmd.exe",
		"ocsf.class_uid":       float64(1007),
		"destination.port":     float64(443),
	})
	if act["process_file_name"] != "cmd.exe" {
		t.Fatalf("process_file_name=%v", act["process_file_name"])
	}
	if act["process_name"] != "cmd.exe" {
		t.Fatalf("process_name=%v", act["process_name"])
	}
	if act["destination_port"] != int64(443) {
		t.Fatalf("destination_port=%v", act["destination_port"])
	}
	if act["ocsf_class_uid"] != int64(1007) {
		t.Fatalf("ocsf_class_uid=%v", act["ocsf_class_uid"])
	}
}

func TestCustomEngineOCSFRule(t *testing.T) {
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
		Expression: `event_type == "process" && process_file_name == "powershell.exe"`,
	}
	if err := e.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	alerts := e.Evaluate(EventToMap(map[string]interface{}{
		"event_type":        "process",
		"process.file.name": "powershell.exe",
		"process.file.path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
	}))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
}
