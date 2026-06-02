package ocsf

import (
	"encoding/json"
	"strings"
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

func TestAlertOCSFNoGoSourceFiles(t *testing.T) {
	t.Parallel()
	env := FromDetectionAlert(AlertInput{
		AlertID:       "alert-nosrc",
		RuleID:        "behavioral-persistence",
		EndpointID:    "ep-2",
		Title:         "Persistence via cron",
		Description:   "Cron job added",
		Severity:      "medium",
		Score:         60,
		Timestamp:     time.Unix(1_700_000_000, 0).UTC(),
		ProcessPID:    1234,
		ProcessName:   "bash",
		ProcessPath:   "/bin/bash",
		CommandLine:   "crontab -e",
		FilePath:      "/etc/crontab",
		TechniqueID:   "T1053.003",
		TechniqueName: "Cron",
		TacticID:      "TA0003",
		TacticName:    "Persistence",
		Confidence:    0.85,
		RiskScore:     60,
		Hostname:      "prod-server-01",
	}, DefaultProduct("1.0.0"))

	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	output := string(b)

	goFilePatterns := []string{".go:", ".go\"", "responder.go", "engine.go", "agent.go", "main.go"}
	for _, pattern := range goFilePatterns {
		if strings.Contains(output, pattern) {
			t.Fatalf("OCSF alert output contains Go source file reference %q:\n%s", pattern, output)
		}
	}

	if strings.Contains(output, "unmapped") {
		t.Fatalf("OCSF alert should not contain unmapped field:\n%s", output)
	}

	if env.Device == nil || env.Device.UID != "ep-2" {
		t.Fatalf("expected device.uid=ep-2, got %+v", env.Device)
	}
	if len(env.Attacks) == 0 || env.Attacks[0].Technique.UID != "T1053.003" {
		t.Fatalf("expected MITRE attack, got %+v", env.Attacks)
	}
	if env.RiskScore != 60 {
		t.Fatalf("risk_score=%d", env.RiskScore)
	}
	if env.ConfidenceID != ConfidenceHigh {
		t.Fatalf("confidence_id=%d", env.ConfidenceID)
	}
}

func TestAlertObservablesPopulated(t *testing.T) {
	t.Parallel()
	env := FromDetectionAlert(AlertInput{
		AlertID:    "alert-obs",
		RuleID:     "ioc-hash-match",
		Title:      "Known malware hash",
		Severity:   "critical",
		Score:      95,
		FilePath:   "/tmp/malware.bin",
		FileSHA256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		DestIP:     "192.168.1.100",
		Domain:     "c2.evil.org",
		URL:        "https://c2.evil.org/beacon",
	}, DefaultProduct("1.0.0"))

	if len(env.Observables) < 4 {
		t.Fatalf("expected >=4 observables, got %d: %+v", len(env.Observables), env.Observables)
	}
	if env.File == nil || len(env.File.Hashes) == 0 {
		t.Fatal("expected file.hashes to be populated")
	}
	if env.File.Hashes[0].Algorithm != "SHA-256" {
		t.Fatalf("hash algorithm=%q", env.File.Hashes[0].Algorithm)
	}
}
