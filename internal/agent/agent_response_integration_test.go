package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

type fakeCollector struct {
	events []schema.ProcessEvent
}

func (f fakeCollector) Name() string { return "fake" }

func (f fakeCollector) Collect(context.Context) ([]collector.Telemetry, error) {
	out := make([]collector.Telemetry, 0, len(f.events))
	for i := range f.events {
		ev := f.events[i]
		out = append(out, collector.Telemetry{Process: &ev})
	}
	return out, nil
}

func TestProcessCycleMonitoringResponseAndAudit(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{}
	cfg.Service.EndpointID = "ep-test"
	cfg.Logging.AlertFile = filepath.Join(dir, "alerts.jsonl")
	cfg.Logging.AuditFile = filepath.Join(dir, "audit.jsonl")
	cfg.LegacyResponse.AllowKill = true
	cfg.LegacyResponse.AutoKillEnabled = true
	cfg.LegacyResponse.MinKillScore = 90
	cfg.LegacyResponse.KillRuleAllowlist = []string{"PROC-CRIT"}
	cfg.LegacyResponse.ProtectedProcesses = []string{"systemd"}

	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:       "PROC-CRIT",
				Name:     "Critical temp shell",
				Severity: "critical",
				When: rules.Condition{
					ChildIn:             []string{"sh"},
					CommandLineContains: []string{"/tmp/"},
				},
			},
		},
	}

	fc := fakeCollector{
		events: []schema.ProcessEvent{
			{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventProcess,
					EndpointID:    cfg.Service.EndpointID,
					Timestamp:     time.Now().UTC(),
					Hostname:      "test-host",
					OS:            "darwin",
				},
				PID:         os.Getpid(),
				PPID:        1,
				ProcessName: "sh",
				ProcessPath: "/bin/sh",
				CommandLine: "/bin/sh /tmp/evil.sh",
				User:        "tester",
			},
		},
	}

	a := NewForTestingWithCollectors(cfg, rs, []collector.Collector{fc})
	if err := a.ProcessCycle(context.Background()); err != nil {
		t.Fatalf("process cycle failed: %v", err)
	}

	alertBytes, err := os.ReadFile(cfg.Logging.AlertFile)
	if err != nil {
		t.Fatalf("read alerts: %v", err)
	}
	if len(alertBytes) == 0 {
		t.Fatal("expected alert log content")
	}

	auditBytes, err := os.ReadFile(cfg.Logging.AuditFile)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(auditBytes) == 0 {
		t.Fatal("expected audit log content")
	}

	var rec schema.AuditRecord
	line := firstLine(string(auditBytes))
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("parse audit line: %v", err)
	}
	if rec.Action != "kill_process" {
		t.Fatalf("unexpected audit action: %s", rec.Action)
	}
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
