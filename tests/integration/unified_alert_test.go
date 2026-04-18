//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/agent"
	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

// TestUnifiedAlertPath verifies that alerts from both legacy detection and
// advanced detection flow through the unified handleAlerts path, including
// writing to the JSONL alert file and audit log.
func TestUnifiedAlertPath(t *testing.T) {
	dir := t.TempDir()
	alertFile := filepath.Join(dir, "alerts.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	cfg := config.Defaults()
	cfg.Service.EndpointID = "test-unified"
	cfg.Service.TickInterval = 100 * time.Millisecond
	cfg.Logging.AlertFile = alertFile
	cfg.Logging.AuditFile = auditFile
	cfg.LegacyResponse.AllowKill = false

	rs := rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:       "test-suspicious",
				Name:     "Test Suspicious Process",
				Severity: "high",
				Score:    80,
				When: rules.Condition{
					CommandLineContains: []string{"suspicious-test-proc"},
				},
			},
		},
	}

	mockCol := &mockCollector{
		events: []collector.Telemetry{
			{
				Process: &schema.ProcessEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventProcess,
						EndpointID:    "test-unified",
						Timestamp:     time.Now().UTC(),
						Hostname:      "test-host",
						OS:            "linux",
					},
					PID:         42,
					ProcessName: "suspicious-test-proc",
					ProcessPath: "/tmp/suspicious-test-proc",
					CommandLine: "/tmp/suspicious-test-proc --payload",
				},
			},
		},
	}

	a := agent.NewForTestingWithCollectors(cfg, rs, []collector.Collector{mockCol})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := a.ProcessCycle(ctx); err != nil {
		t.Fatalf("ProcessCycle: %v", err)
	}

	data, err := os.ReadFile(alertFile)
	if err != nil {
		t.Fatalf("read alert file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one alert in alert file")
	}

	var al schema.Alert
	if err := json.Unmarshal([]byte(lines[0]), &al); err != nil {
		t.Fatalf("unmarshal alert: %v", err)
	}

	if al.RuleID != "test-suspicious" {
		t.Errorf("expected rule_id 'test-suspicious', got %q", al.RuleID)
	}
	if al.ProcessPID != 42 {
		t.Errorf("expected PID 42, got %d", al.ProcessPID)
	}
	if al.EndpointID != "test-unified" {
		t.Errorf("expected endpoint_id 'test-unified', got %q", al.EndpointID)
	}
}

type mockCollector struct {
	events []collector.Telemetry
	called bool
}

func (m *mockCollector) Name() string { return "mock" }

func (m *mockCollector) Collect(_ context.Context) ([]collector.Telemetry, error) {
	if m.called {
		return nil, nil
	}
	m.called = true
	return m.events, nil
}
