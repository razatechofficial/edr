package alert

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestWriteAlertAndAudit(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "alerts.jsonl"), filepath.Join(dir, "audit.jsonl"), 1024)
	if err := w.WriteAlert(schema.Alert{
		SchemaVersion: schema.SchemaVersionV1,
		AlertID:       "a1",
		RuleID:        "r1",
		Timestamp:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("write alert: %v", err)
	}
	if err := w.WriteAudit(schema.AuditRecord{
		SchemaVersion: schema.SchemaVersionV1,
		RecordID:      "x1",
		Timestamp:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alerts.jsonl")); err != nil {
		t.Fatalf("missing alerts file: %v", err)
	}
}
