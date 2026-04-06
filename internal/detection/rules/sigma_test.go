package rules

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

const testSigmaRule = `title: Suspicious PowerShell Execution
id: test-rule-001
status: test
level: high
description: Detects suspicious powershell.exe execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: powershell.exe
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
`

func writeSigmaRule(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "test_rule.yml"), []byte(testSigmaRule), 0o644); err != nil {
		t.Fatalf("write sigma rule: %v", err)
	}
}

func TestSigmaEngineLoadRules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeSigmaRule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewSigmaEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewSigmaEngine: %v", err)
	}
	defer engine.Stop()

	if engine.Count() != 1 {
		t.Errorf("Count() = %d, want 1", engine.Count())
	}
}

func TestSigmaEngineEvaluateMatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeSigmaRule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewSigmaEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewSigmaEngine: %v", err)
	}
	defer engine.Stop()

	event := map[string]interface{}{
		"process_name": "powershell.exe",
		"command_line": "powershell -enc base64payload",
	}
	alerts := engine.Evaluate(event)
	if len(alerts) == 0 {
		t.Fatal("Evaluate returned 0 alerts for matching event")
	}
	if alerts[0].Title != "Suspicious PowerShell Execution" {
		t.Errorf("Title = %q, want %q", alerts[0].Title, "Suspicious PowerShell Execution")
	}
}

func TestSigmaEngineEvaluateNoMatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeSigmaRule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewSigmaEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewSigmaEngine: %v", err)
	}
	defer engine.Stop()

	event := map[string]interface{}{
		"process_name": "notepad.exe",
	}
	alerts := engine.Evaluate(event)
	if len(alerts) != 0 {
		t.Errorf("Evaluate returned %d alerts for non-matching event, want 0", len(alerts))
	}
}

func TestSigmaEngineCount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeSigmaRule(t, dir)
	os.WriteFile(filepath.Join(dir, "second.yaml"), []byte(`title: Second Rule
id: test-rule-002
status: test
level: low
description: Another rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: cmd.exe
    condition: selection
`), 0o644)

	logger, _ := zap.NewDevelopment()
	engine, err := NewSigmaEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewSigmaEngine: %v", err)
	}
	defer engine.Stop()

	if engine.Count() != 2 {
		t.Errorf("Count() = %d, want 2", engine.Count())
	}
}
