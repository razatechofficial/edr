package agent

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func TestEnsureAlertOCSF(t *testing.T) {
	t.Parallel()
	al := &schema.Alert{
		AlertID:     "a1",
		RuleID:      "rule-1",
		EndpointID:  "ep-1",
		Title:       "Test alert",
		Description: "desc",
		Severity:    schema.SeverityHigh,
		Score:       85,
		Timestamp:   time.Unix(1_700_000_000, 0).UTC(),
		ProcessName: "evil.exe",
	}
	ensureAlertOCSF(al, ocsf.DefaultProduct("test"))
	if len(al.OCSF) == 0 {
		t.Fatal("expected OCSF on alert")
	}
	if int(al.OCSF["class_uid"].(float64)) != ocsf.ClassUIDDetectionFinding {
		t.Fatalf("class_uid=%v", al.OCSF["class_uid"])
	}
}

func TestEnsureAlertOCSFPreservesExisting(t *testing.T) {
	t.Parallel()
	existing := map[string]any{"class_uid": float64(9999)}
	al := &schema.Alert{OCSF: existing}
	ensureAlertOCSF(al, ocsf.DefaultProduct("test"))
	if al.OCSF["class_uid"].(float64) != 9999 {
		t.Fatal("expected existing OCSF to be preserved")
	}
}
