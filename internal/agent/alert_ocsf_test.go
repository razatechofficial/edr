package agent

import (
	"encoding/json"
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
	ensureAlertOCSF(al, "test")
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
	ensureAlertOCSF(al, "test")
	if al.OCSF["class_uid"].(float64) != 9999 {
		t.Fatal("expected existing OCSF to be preserved")
	}
}

func TestMarshalAlertOCSFRootEnvelope(t *testing.T) {
	t.Parallel()
	al := schema.Alert{
		AlertID:  "a1",
		RuleID:   "rule-1",
		Title:    "Test",
		Severity: schema.SeverityHigh,
	}
	ensureAlertOCSF(&al, "test")
	body, err := marshalAlertOCSF(al, "test")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if int(doc["class_uid"].(float64)) != ocsf.ClassUIDDetectionFinding {
		t.Fatalf("class_uid=%v", doc["class_uid"])
	}
	if doc["alert_id"] != nil {
		t.Fatalf("unexpected flat alert_id field: %v", doc["alert_id"])
	}
}
