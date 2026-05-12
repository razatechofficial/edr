package detection

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestFromSchemaAlertMapsYARASource(t *testing.T) {
	d := FromSchemaAlert(schema.Alert{
		AlertID:   "a1",
		RuleID:    "yara-EICAR_Test_File",
		Title:     "YARA match: EICAR_Test_File",
		Timestamp: time.Now().UTC(),
		FilePath:  "/tmp/eicar_test.txt",
	})
	if d.Source != SourceYARA {
		t.Fatalf("source = %v, want SourceYARA", d.Source)
	}
	if d.Event == nil || d.Event.File == nil || d.Event.File.Path != "/tmp/eicar_test.txt" {
		t.Fatalf("file payload missing: %+v", d.Event)
	}
}
