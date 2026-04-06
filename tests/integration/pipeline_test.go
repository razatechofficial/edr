//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/detection/ioc"
	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/testutil"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

func TestFullPipelineE2E(t *testing.T) {
	logger := zap.NewNop()

	knownBadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	matcher := ioc.NewMatcher(logger)
	matcher.Hashes().Add(ioc.HashEntry{
		Hash:          knownBadHash,
		Type:          ioc.HashSHA256,
		MalwareFamily: "TestMalware",
		Source:        "unit-test",
		Severity:      "critical",
		Tags:          []string{"test", "malware"},
	})

	processEvent := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			Timestamp:     time.Now().UTC(),
			Hostname:      "test-host",
			OS:            "linux",
		},
		PID:         1234,
		PPID:        1,
		ProcessName: "malicious",
		ProcessPath: "/tmp/malicious",
		CommandLine: "/tmp/malicious --steal-data",
		User:        "nobody",
		Hashes:      []string{knownBadHash},
	}

	data, err := json.Marshal(processEvent)
	if err != nil {
		t.Fatalf("marshal process event: %v", err)
	}

	rb := kernel.NewRingBuffer(4096)
	driver := testutil.NewMockDriver()

	if err := rb.Write(data); err != nil {
		t.Fatalf("write to ring buffer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := driver.Start(ctx, rb); err != nil {
		t.Fatalf("start mock driver: %v", err)
	}
	defer driver.Stop()

	readData, err := rb.TryRead()
	if err != nil {
		t.Fatalf("read from ring buffer: %v", err)
	}
	if readData == nil {
		t.Fatal("expected data from ring buffer, got nil")
	}

	var decoded schema.ProcessEvent
	if err := json.Unmarshal(readData, &decoded); err != nil {
		t.Fatalf("unmarshal process event: %v", err)
	}

	matches := matcher.CheckEvent(&decoded)
	if len(matches) == 0 {
		t.Fatal("expected IOC match for known-bad hash, got none")
	}

	match := matches[0]
	if !match.Matched {
		t.Error("expected match.Matched to be true")
	}
	if match.Type != "hash" {
		t.Errorf("expected match type 'hash', got %q", match.Type)
	}
	if match.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", match.Severity)
	}
	if match.MalwareFamily != "TestMalware" {
		t.Errorf("expected malware family 'TestMalware', got %q", match.MalwareFamily)
	}
}

func TestPipelineCleanEventNoAlert(t *testing.T) {
	logger := zap.NewNop()
	matcher := ioc.NewMatcher(logger)

	cleanEvent := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			Timestamp:     time.Now().UTC(),
			Hostname:      "test-host",
		},
		PID:         5678,
		PPID:        1,
		ProcessName: "clean-process",
		ProcessPath: "/usr/bin/clean",
		CommandLine: "/usr/bin/clean --safe",
		Hashes:      []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}

	matches := matcher.CheckEvent(cleanEvent)
	if len(matches) != 0 {
		t.Errorf("expected no IOC matches for clean event, got %d", len(matches))
	}
}

func TestPipelineAlertSeverityMapping(t *testing.T) {
	tests := []struct {
		name     string
		severity events.Severity
		want     string
	}{
		{"info", events.SeverityInfo, "info"},
		{"low", events.SeverityLow, "low"},
		{"medium", events.SeverityMedium, "medium"},
		{"high", events.SeverityHigh, "high"},
		{"critical", events.SeverityCritical, "critical"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			alert := testutil.MakeAlert(tc.severity, "Test Alert", "test-rule-"+tc.name)
			if string(alert.Severity) != tc.want {
				t.Errorf("alert severity = %q, want %q", alert.Severity, tc.want)
			}
		})
	}
}
