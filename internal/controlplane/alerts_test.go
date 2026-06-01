package controlplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListRecentAlerts(t *testing.T) {
	dir := t.TempDir()
	reg, err := NewRegistry(RegistryConfig{DataDir: dir, HeartbeatSec: 30})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "alerts.jsonl")
	if err := os.WriteFile(path, []byte(`{"alert_id":"a1","title":"one"}
{"alert_id":"a2","title":"two"}
{"alert_id":"a3","title":"three"}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	alerts, err := reg.ListRecentAlerts(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts len = %d", len(alerts))
	}
	if alerts[0]["alert_id"] != "a2" {
		t.Fatalf("first alert = %v", alerts[0]["alert_id"])
	}
	if alerts[1]["alert_id"] != "a3" {
		t.Fatalf("second alert = %v", alerts[1]["alert_id"])
	}
}

func TestListRecentAlertsMissingFile(t *testing.T) {
	reg, err := NewRegistry(RegistryConfig{DataDir: t.TempDir(), HeartbeatSec: 30})
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := reg.ListRecentAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected empty alerts, got %d", len(alerts))
	}
}
