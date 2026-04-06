package forwarder

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestAppendAndDrainSpool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.jsonl")
	a := schema.Alert{
		SchemaVersion: schema.SchemaVersionV1,
		AlertID:       "a1",
		RuleID:        "R1",
		Timestamp:     time.Now().UTC(),
	}
	if err := AppendSpool(path, a); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := DrainSpool(path, func(schema.Alert) error {
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 drained, got %d", n)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected spool removed after successful drain")
	}
}
