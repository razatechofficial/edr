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
				}{
					ProcessPathContains: []string{"/tmp/"},
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
		ProcessPath: "/tmp/run.sh",
		PID:         123,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
	if alerts[0].Score != 80 {
		t.Fatalf("unexpected score %d", alerts[0].Score)
	}
}
