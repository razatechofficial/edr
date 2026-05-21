package ocsf

import (
	"testing"
	"time"
)

func TestFromDetectionAlert(t *testing.T) {
	t.Parallel()
	env := FromDetectionAlert(AlertInput{
		AlertID:     "alert-1",
		RuleID:      "OCSF-TEST",
		EndpointID:  "ep-1",
		Title:       "Suspicious process",
		Description: "cmd.exe spawned powershell",
		Severity:    "high",
		Score:       80,
		Timestamp:   time.Unix(1_700_000_000, 0).UTC(),
		ProcessPID:  4242,
		ProcessName: "powershell.exe",
		ProcessPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		FilePath:    `C:\Users\test\payload.exe`,
		DestIP:      "10.0.0.5",
		DestPort:    443,
		Domain:      "evil.example",
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDDetectionFinding {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Finding == nil || env.Finding.Title != "Suspicious process" {
		t.Fatalf("finding=%+v", env.Finding)
	}
	if env.Process == nil || env.Process.PID != 4242 {
		t.Fatalf("process=%+v", env.Process)
	}
	if env.File == nil || env.File.Path == "" {
		t.Fatal("expected file object")
	}
	if env.DstEndpoint == nil || env.DstEndpoint.IP != "10.0.0.5" {
		t.Fatalf("dst=%+v", env.DstEndpoint)
	}
}

func TestAlertSeverityFromScore(t *testing.T) {
	t.Parallel()
	id, name := alertSeverity("", 92)
	if id != 5 || name != "Critical" {
		t.Fatalf("severity=%d %s", id, name)
	}
}
