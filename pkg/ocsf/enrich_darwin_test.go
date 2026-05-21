package ocsf

import "testing"

func TestEnrichDarwinSigmaFieldsESFExec(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"os":           "darwin",
		"esf_type":     9,
		"esf_op":       "exec",
		"process_path": "/usr/bin/curl",
		"command_line": "curl https://example.com",
	})
	if out["esf.event_type"] != 9 {
		t.Fatalf("esf.event_type=%v", out["esf.event_type"])
	}
	if out["event.action"] != "exec" {
		t.Fatalf("event.action=%v", out["event.action"])
	}
	if out["Image"] != "/usr/bin/curl" {
		t.Fatalf("Image=%v", out["Image"])
	}
}

func TestEnrichDarwinSigmaFieldsSignalTarget(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"os":           "darwin",
		"esf_type":     27,
		"esf_op":       "signal",
		"process_path": "/Applications/Little Snitch.app/Contents/MacOS/Little Snitch",
		"signal_number": 9,
	})
	if out["TargetImage"] == "" {
		t.Fatalf("TargetImage missing: %v", out)
	}
	if out["SignalNumber"] != 9 {
		t.Fatalf("SignalNumber=%v", out["SignalNumber"])
	}
}

func TestEnrichDarwinSigmaFieldsUnifiedLog(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"os":        "darwin",
		"subsystem": "com.apple.sudo",
		"category":  "sudo",
		"message":   "sudo: TTY=console USER=root ; COMMAND=/bin/ls",
	})
	if out["subsystem"] != "com.apple.sudo" {
		t.Fatalf("subsystem=%v", out["subsystem"])
	}
	if out["CommandLine"] == "" {
		t.Fatalf("CommandLine not set from message")
	}
	if out["category"] != "sudo" {
		t.Fatalf("category=%v", out["category"])
	}
}
