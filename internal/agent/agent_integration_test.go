package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

type staticProcessCollector struct {
	event collector.Telemetry
}

func (s staticProcessCollector) Name() string { return "static_process" }

func (s staticProcessCollector) Collect(context.Context) ([]collector.Telemetry, error) {
	return []collector.Telemetry{s.event}, nil
}

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
				When: rules.Condition{
					ProcessPathContains: []string{"/"},
				},
			},
		},
	}

	mockProcess := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    cfg.Service.EndpointID,
			Timestamp:     time.Now().UTC(),
			Hostname:      "test-host",
			OS:            "darwin",
		},
		PID:         os.Getpid(),
		PPID:        os.Getppid(),
		ProcessName: "test-process",
		ProcessPath: os.Args[0],
		CommandLine: os.Args[0],
		User:        "tester",
	}
	a := NewForTestingWithCollectors(cfg, rs, []collector.Collector{
		staticProcessCollector{event: collector.Telemetry{Process: mockProcess}},
	})
	if err := a.ProcessCycle(context.Background()); err != nil {
		t.Fatalf("process cycle: %v", err)
	}
	if _, err := os.Stat(cfg.Logging.AlertFile); err != nil {
		t.Fatalf("expected alert file to exist: %v", err)
	}
}
