package alert

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func TestParseAlertLineOCSFRoundTrip(t *testing.T) {
	t.Parallel()
	src := schema.Alert{
		SchemaVersion: schema.SchemaVersionV1,
		AlertID:       "alert-1",
		RuleID:        "RULE-001",
		EndpointID:    "ep-1",
		Severity:      schema.SeverityHigh,
		Score:         85,
		Title:         "Suspicious process",
		Description:   "powershell encoded command",
		Timestamp:     time.Unix(1_700_000_000, 0).UTC(),
		ProcessPID:    4242,
		ProcessName:   "powershell.exe",
		ProcessPath:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:   "powershell -enc ABC",
		DestIP:        "10.0.0.5",
		DestPort:      443,
		Domain:        "evil.example",
		FileSHA256:    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	line, err := MarshalOCSF(src, "test")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAlertLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if got.AlertID != src.AlertID {
		t.Fatalf("AlertID=%q", got.AlertID)
	}
	if got.RuleID != src.RuleID {
		t.Fatalf("RuleID=%q", got.RuleID)
	}
	if got.Title != src.Title {
		t.Fatalf("Title=%q", got.Title)
	}
	if got.ProcessPID != src.ProcessPID {
		t.Fatalf("ProcessPID=%d", got.ProcessPID)
	}
	if got.ProcessName != src.ProcessName {
		t.Fatalf("ProcessName=%q", got.ProcessName)
	}
	if got.DestIP != src.DestIP {
		t.Fatalf("DestIP=%q", got.DestIP)
	}
	if got.Domain != src.Domain {
		t.Fatalf("Domain=%q", got.Domain)
	}
	if got.FileSHA256 != src.FileSHA256 {
		t.Fatalf("FileSHA256=%q", got.FileSHA256)
	}
	if int(got.OCSF["class_uid"].(float64)) != ocsf.ClassUIDDetectionFinding {
		t.Fatalf("class_uid=%v", got.OCSF["class_uid"])
	}
}

func TestParseAlertLineLegacyFlat(t *testing.T) {
	t.Parallel()
	line := []byte(`{"schema_version":"v1","alert_id":"a1","rule_id":"r1","severity":"high","title":"Legacy alert","timestamp":"2024-01-02T03:04:05Z"}`)
	got, err := ParseAlertLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if got.AlertID != "a1" || got.RuleID != "r1" || got.Title != "Legacy alert" {
		t.Fatalf("got=%+v", got)
	}
}
