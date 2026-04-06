package rules

import (
	"testing"

	"go.uber.org/zap"
)

func newTestCustomEngine(t *testing.T) *CustomEngine {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	engine, err := NewCustomEngine(logger)
	if err != nil {
		t.Fatalf("NewCustomEngine: %v", err)
	}
	return engine
}

func TestCustomEngineCELRule(t *testing.T) {
	t.Parallel()
	engine := newTestCustomEngine(t)

	err := engine.AddRule(CustomRule{
		ID:         "CEL-001",
		Name:       "Evil process",
		Severity:   "high",
		Expression: `process_name == "evil.exe"`,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	alerts := engine.Evaluate(map[string]interface{}{
		"process_name": "evil.exe",
	})
	if len(alerts) == 0 {
		t.Fatal("Evaluate returned 0 alerts for matching event")
	}
	if alerts[0].RuleName != "Evil process" {
		t.Errorf("RuleName = %q, want %q", alerts[0].RuleName, "Evil process")
	}
}

func TestCustomEngineCELNoMatch(t *testing.T) {
	t.Parallel()
	engine := newTestCustomEngine(t)

	engine.AddRule(CustomRule{
		ID:         "CEL-001",
		Name:       "Evil process",
		Expression: `process_name == "evil.exe"`,
		Enabled:    true,
	})

	alerts := engine.Evaluate(map[string]interface{}{
		"process_name": "notepad.exe",
	})
	if len(alerts) != 0 {
		t.Errorf("Evaluate returned %d alerts, want 0", len(alerts))
	}
}

func TestCustomEngineMultipleRules(t *testing.T) {
	t.Parallel()
	engine := newTestCustomEngine(t)

	rules := []CustomRule{
		{ID: "R1", Name: "rule-A", Expression: `process_name == "a.exe"`, Enabled: true},
		{ID: "R2", Name: "rule-B", Expression: `process_name == "b.exe"`, Enabled: true},
		{ID: "R3", Name: "rule-C", Expression: `process_name == "c.exe"`, Enabled: true},
	}
	for _, r := range rules {
		if err := engine.AddRule(r); err != nil {
			t.Fatalf("AddRule(%s): %v", r.ID, err)
		}
	}

	alerts := engine.Evaluate(map[string]interface{}{
		"process_name": "b.exe",
	})
	if len(alerts) != 1 {
		t.Fatalf("Evaluate returned %d alerts, want 1", len(alerts))
	}
	if alerts[0].RuleID != "R2" {
		t.Errorf("RuleID = %q, want %q", alerts[0].RuleID, "R2")
	}
}

func TestCustomEngineComplexExpression(t *testing.T) {
	t.Parallel()
	engine := newTestCustomEngine(t)

	engine.AddRule(CustomRule{
		ID:         "COMPLEX-001",
		Name:       "Complex rule",
		Expression: `process_name == "cmd.exe" && command_line.contains("whoami")`,
		Enabled:    true,
	})

	tests := []struct {
		name    string
		vars    map[string]interface{}
		matched bool
	}{
		{
			name:    "both conditions met",
			vars:    map[string]interface{}{"process_name": "cmd.exe", "command_line": "cmd /c whoami"},
			matched: true,
		},
		{
			name:    "wrong process",
			vars:    map[string]interface{}{"process_name": "powershell.exe", "command_line": "whoami"},
			matched: false,
		},
		{
			name:    "wrong command",
			vars:    map[string]interface{}{"process_name": "cmd.exe", "command_line": "dir"},
			matched: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alerts := engine.Evaluate(tc.vars)
			got := len(alerts) > 0
			if got != tc.matched {
				t.Errorf("matched = %v, want %v", got, tc.matched)
			}
		})
	}
}
