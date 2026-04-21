package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

type fileBatchCollector struct {
	batches [][]collector.Telemetry
	i       int
}

func (f *fileBatchCollector) Name() string { return "file_batches" }

func (f *fileBatchCollector) Collect(context.Context) ([]collector.Telemetry, error) {
	if f.i >= len(f.batches) {
		return nil, nil
	}
	out := f.batches[f.i]
	f.i++
	return out, nil
}

func fileDedupTestEvent(path string) *schema.FileEvent {
	return &schema.FileEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventFile,
			EndpointID:    "ep-dedup",
			Timestamp:     time.Now().UTC(),
			Hostname:      "h",
			OS:            "linux",
		},
		Path:      path,
		Operation: "write",
		ActorPID:  42,
	}
}

func TestProcessCycleFileDedupeWindow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dedup_marker_path")
	cfg := config.Config{}
	cfg.Service.EndpointID = "ep-test"
	cfg.Logging.AlertFile = filepath.Join(dir, "alerts.jsonl")
	cfg.Logging.AuditFile = filepath.Join(dir, "audit.jsonl")

	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:         "FILE-DEDUP",
				Name:       "file dedup test",
				Severity:   "high",
				EventType:  "file",
				When: rules.Condition{FilePathContains: []string{p}},
			},
		},
	}

	fe := fileDedupTestEvent(p)
	mock := &fileBatchCollector{
		batches: [][]collector.Telemetry{
			{{File: fe}, {File: fe}, {File: fe}},
			{{File: fe}},
		},
	}

	a := NewForTestingWithCollectors(cfg, rs, []collector.Collector{mock})
	if err := a.ProcessCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(cfg.Logging.AlertFile)
	n1 := countNonEmptyLines(string(b1))
	if n1 != 1 {
		t.Fatalf("after 3 dupes want 1 alert line, got %d body %q", n1, string(b1))
	}

	time.Sleep(550 * time.Millisecond)
	if err := a.ProcessCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(cfg.Logging.AlertFile)
	n2 := countNonEmptyLines(string(b2))
	if n2 != 2 {
		t.Fatalf("after window want 2 alert lines, got %d body %q", n2, string(b2))
	}
}

func countNonEmptyLines(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
