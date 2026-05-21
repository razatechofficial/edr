package alert

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func TestWithOCSFContextFillsFlatFields(t *testing.T) {
	env := ocsf.FromDetectionAlert(ocsf.AlertInput{
		AlertID:     "ocsf-1",
		RuleID:      "RULE-TEST",
		Title:       "Suspicious process",
		Description: "test",
		Severity:    "high",
		Timestamp:   time.Unix(1_700_000_000, 0).UTC(),
		ProcessPID:  4242,
		ProcessName: "evil.exe",
		ProcessPath: "/tmp/evil.exe",
		CommandLine: "evil.exe -bad",
		FilePath:    "/tmp/payload.bin",
		FileSHA256:  "abc123",
		DestIP:      "203.0.113.1",
		Domain:      "evil.example",
	}, ocsf.DefaultProduct("test"))
	raw := ocsf.EnvelopeToMap(env)

	got := WithOCSFContext(schema.Alert{OCSF: raw})
	if got.AlertID != "ocsf-1" {
		t.Fatalf("AlertID = %q", got.AlertID)
	}
	if got.ProcessPID != 4242 || got.ProcessName != "evil.exe" {
		t.Fatalf("process: pid=%d name=%q", got.ProcessPID, got.ProcessName)
	}
	if got.FilePath != "/tmp/payload.bin" || got.DestIP != "203.0.113.1" {
		t.Fatalf("file/network: path=%q dest=%q", got.FilePath, got.DestIP)
	}
}

func TestWithOCSFContextPreservesPrimaryFields(t *testing.T) {
	env := ocsf.FromDetectionAlert(ocsf.AlertInput{
		AlertID:    "from-ocsf",
		ProcessPID: 1,
	}, ocsf.DefaultProduct("test"))
	raw := ocsf.EnvelopeToMap(env)

	got := WithOCSFContext(schema.Alert{
		OCSF:        raw,
		AlertID:     "primary-id",
		ProcessPID:  99,
		ProcessName: "keep.exe",
	})
	if got.AlertID != "primary-id" || got.ProcessPID != 99 || got.ProcessName != "keep.exe" {
		t.Fatalf("primary overwritten: %+v", got)
	}
}
