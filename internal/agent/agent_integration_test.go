package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/rules"
)

func TestProcessCycleWritesAlertFile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{}
	cfg.Service.EndpointID = "ep-test"
	cfg.Service.TickInterval = time.Millisecond * 50
	cfg.Logging.AlertFile = filepath.Join(dir, "alerts.jsonl")
	cfg.Logging.AuditFile = filepath.Join(dir, "audit.jsonl")
	cfg.LegacyResponse.AllowKill = false

	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:       "PROC-TEST",
				Name:     "Any process with path",
				Severity: "high",
				When: struct {
					ParentIn            []string "yaml:\"parent_in\""
					ChildIn             []string "yaml:\"child_in\""
					ProcessPathContains []string "yaml:\"process_path_contains\""
					CommandLineContains []string "yaml:\"command_line_contains\""
					CommandLineAll      []string "yaml:\"command_line_all_contains\""
				}{
					ProcessPathContains: []string{"/"},
				},
			},
		},
	}

	a, err := NewForTesting(cfg, rs)
	if err != nil {
		t.Fatalf("new test agent: %v", err)
	}
	if err := a.ProcessCycle(context.Background()); err != nil {
		t.Fatalf("process cycle: %v", err)
	}
	if _, err := os.Stat(cfg.Logging.AlertFile); err != nil {
		t.Fatalf("expected alert file to exist: %v", err)
	}
}
