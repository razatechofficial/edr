package events_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/razatechofficial/edr/internal/collectors"
	"github.com/razatechofficial/edr/pkg/events"
)

func TestEventTypeString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		et   events.EventType
		want string
	}{
		{events.EventProcess, "process"},
		{events.EventFile, "file"},
		{events.EventNetwork, "network"},
		{events.EventRegistry, "registry"},
		{events.EventMemory, "memory"},
		{events.EventDNS, "dns"},
		{events.EventAuth, "auth"},
		{events.EventModule, "module"},
		{events.EventMount, "mount"},
		{events.EventPtrace, "ptrace"},
		{events.EventSignal, "signal"},
	}
	for _, tc := range tests {
		if string(tc.et) != tc.want {
			t.Errorf("EventType %q != %q", string(tc.et), tc.want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  events.Severity
		want string
	}{
		{events.SeverityInfo, "info"},
		{events.SeverityLow, "low"},
		{events.SeverityMedium, "medium"},
		{events.SeverityHigh, "high"},
		{events.SeverityCritical, "critical"},
	}
	for _, tc := range tests {
		if string(tc.sev) != tc.want {
			t.Errorf("Severity %q != %q", string(tc.sev), tc.want)
		}
	}
}

func TestNewKernelEvent(t *testing.T) {
	t.Parallel()
	id := uuid.New().String()
	now := time.Now().UTC()

	alert := events.Alert{
		ID:          id,
		RuleID:      "RULE-001",
		RuleName:    "Test Rule",
		Severity:    events.SeverityHigh,
		Title:       "Suspicious Process",
		Description: "Process matched known malware hash",
		Timestamp:   now,
		MITRE: []events.MITREAttack{{
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			TacticID:      "TA0002",
			TacticName:    "Execution",
		}},
		Tags: []string{"malware", "critical"},
	}

	if _, err := uuid.Parse(alert.ID); err != nil {
		t.Errorf("ID is not a valid UUID: %v", err)
	}
	if alert.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if alert.Severity != events.SeverityHigh {
		t.Errorf("Severity = %q, want %q", alert.Severity, events.SeverityHigh)
	}
	if len(alert.MITRE) != 1 {
		t.Fatalf("MITRE len = %d, want 1", len(alert.MITRE))
	}
	if alert.MITRE[0].TechniqueID != "T1059" {
		t.Errorf("MITRE TechniqueID = %q, want %q", alert.MITRE[0].TechniqueID, "T1059")
	}
}

func TestProcessExecEventJSON(t *testing.T) {
	t.Parallel()
	original := collectors.ProcessExecEvent{
		Timestamp:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		PID:        1234,
		TID:        5678,
		PPID:       1,
		UID:        0,
		GID:        0,
		User:       "root",
		ExePath:    "/usr/bin/bash",
		Args:       []string{"-c", "echo hello"},
		Cwd:        "/home/user",
		SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ParentComm: "sshd",
		IsElevated: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded collectors.ProcessExecEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.PID != original.PID {
		t.Errorf("PID = %d, want %d", decoded.PID, original.PID)
	}
	if decoded.ExePath != original.ExePath {
		t.Errorf("ExePath = %q, want %q", decoded.ExePath, original.ExePath)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.IsElevated != original.IsElevated {
		t.Errorf("IsElevated = %v, want %v", decoded.IsElevated, original.IsElevated)
	}
	if decoded.SHA256 != original.SHA256 {
		t.Errorf("SHA256 = %q, want %q", decoded.SHA256, original.SHA256)
	}
	if len(decoded.Args) != len(original.Args) {
		t.Fatalf("Args len = %d, want %d", len(decoded.Args), len(original.Args))
	}
}

func TestAlertJSON(t *testing.T) {
	t.Parallel()
	original := events.Alert{
		ID:          "alert-001",
		RuleID:      "SIGMA-001",
		RuleName:    "Suspicious PowerShell",
		Severity:    events.SeverityCritical,
		Title:       "PowerShell Download Cradle",
		Description: "Encoded command detected",
		Timestamp:   time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		MITRE: []events.MITREAttack{
			{TechniqueID: "T1059.001", TechniqueName: "PowerShell", TacticID: "TA0002", TacticName: "Execution"},
			{TechniqueID: "T1105", TechniqueName: "Ingress Tool Transfer", TacticID: "TA0011", TacticName: "Command and Control"},
		},
		Tags: []string{"powershell", "download"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded events.Alert
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity = %q, want %q", decoded.Severity, original.Severity)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if len(decoded.MITRE) != 2 {
		t.Fatalf("MITRE len = %d, want 2", len(decoded.MITRE))
	}
	if len(decoded.Tags) != 2 {
		t.Fatalf("Tags len = %d, want 2", len(decoded.Tags))
	}
}

func TestAllEventTypesSerializable(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	testCases := []struct {
		name string
		evt  any
	}{
		{"ProcessExec", &collectors.ProcessExecEvent{Timestamp: now, PID: 1, ExePath: "/bin/sh"}},
		{"ProcessExit", &collectors.ProcessExitEvent{Timestamp: now, PID: 1, ExitCode: 0}},
		{"ProcessFork", &collectors.ProcessForkEvent{Timestamp: now, ParentPID: 1, ChildPID: 2}},
		{"FileOpen", &collectors.FileOpenEvent{Timestamp: now, PID: 1, Path: "/tmp/test"}},
		{"FileWrite", &collectors.FileWriteEvent{Timestamp: now, PID: 1, Path: "/tmp/test", Entropy: 3.5}},
		{"FileDelete", &collectors.FileDeleteEvent{Timestamp: now, PID: 1, Path: "/tmp/old"}},
		{"FileRename", &collectors.FileRenameEvent{Timestamp: now, PID: 1, OldPath: "/a", NewPath: "/b"}},
		{"FileCreate", &collectors.FileCreateEvent{Timestamp: now, PID: 1, Path: "/tmp/new"}},
		{"NetworkConnect", &collectors.NetworkConnectEvent{Timestamp: now, PID: 1, Protocol: "tcp", DstAddr: "10.0.0.1", DstPort: 443}},
		{"NetworkAccept", &collectors.NetworkAcceptEvent{Timestamp: now, PID: 1, Protocol: "tcp"}},
		{"NetworkBind", &collectors.NetworkBindEvent{Timestamp: now, PID: 1, Protocol: "udp", Port: 53}},
		{"DNS", &collectors.DNSEvent{Timestamp: now, PID: 1, QueryName: "example.com", QueryType: "A"}},
		{"USB", &collectors.USBEvent{Timestamp: now, Action: "insert", Vendor: "1234", Product: "5678"}},
		{"Alert", &events.Alert{ID: "a-1", Severity: events.SeverityHigh, Timestamp: now}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tc.evt)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("Marshal produced empty output")
			}

			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("Unmarshal to map: %v", err)
			}
			if len(m) == 0 {
				t.Fatal("empty object after unmarshal")
			}
		})
	}
}
