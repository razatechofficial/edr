// Tests for manifest parsing and model management helpers in updater.go.
// These tests do not require ONNX runtime -- they test pure Go logic.

//go:build cgo && (linux || darwin || windows)

package ml

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewModelManager_NilKey(t *testing.T) {
	m := NewModelManager(nil)
	if m.pubKey != nil {
		t.Error("nil key should result in nil pubKey")
	}
	if m.Count() != 0 {
		t.Error("new manager should have zero models")
	}
}

func TestNewModelManager_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	m := NewModelManager(key)
	if m.pubKey == nil {
		t.Error("32-byte key should be accepted")
	}
}

func TestNewModelManager_ShortKey(t *testing.T) {
	key := make([]byte, 16)
	m := NewModelManager(key)
	if m.pubKey != nil {
		t.Error("short key should be rejected")
	}
}

func TestModelManager_GetMissing(t *testing.T) {
	m := NewModelManager(nil)
	_, err := m.Get("nonexistent")
	if err == nil {
		t.Error("expected error for missing model")
	}
}

func TestModelManager_Close_Empty(t *testing.T) {
	m := NewModelManager(nil)
	m.Close()
	if m.Count() != 0 {
		t.Error("close on empty manager should be safe")
	}
}

func TestLoadManifest_NotFound(t *testing.T) {
	m := NewModelManager(nil)
	err := m.LoadManifest("/nonexistent/dir")
	if err != nil {
		t.Error("missing manifest should return nil, not error")
	}
	if m.manifest != nil {
		t.Error("manifest should remain nil when file not found")
	}
}

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	data := `{
		"version": "1.0.0",
		"generated_at": "2026-01-01T00:00:00Z",
		"models": [
			{
				"name": "pe_classifier",
				"version": "1.0.0",
				"file": "pe_classifier.onnx",
				"sha256": "abc123",
				"source": "ember2018",
				"status": "active",
				"size_bytes": 1024
			},
			{
				"name": "pe_classifier",
				"version": "0.9.0",
				"file": "pe_classifier_v090.onnx",
				"sha256": "def456",
				"source": "synthetic",
				"status": "archived",
				"size_bytes": 512
			},
			{
				"name": "behavior_lstm",
				"version": "1.0.0",
				"file": "behavior_lstm.onnx",
				"sha256": "ghi789",
				"source": "cape",
				"status": "active",
				"size_bytes": 2048,
				"metrics": {"accuracy": 0.95, "f1": 0.93}
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewModelManager(nil)
	if err := m.LoadManifest(dir); err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}
	if m.manifest == nil {
		t.Fatal("manifest should be loaded")
	}
	if len(m.manifest.Models) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(m.manifest.Models))
	}
}

func TestLoadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{invalid}"), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewModelManager(nil)
	err := m.LoadManifest(dir)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestActiveVersion(t *testing.T) {
	m := NewModelManager(nil)
	m.manifest = &Manifest{
		Models: []ManifestEntry{
			{Name: "pe_classifier", Version: "1.0.0", Status: "active"},
			{Name: "pe_classifier", Version: "0.9.0", Status: "archived"},
			{Name: "behavior_lstm", Version: "1.0.0", Status: "active"},
		},
	}

	entry := m.ActiveVersion("pe_classifier")
	if entry == nil {
		t.Fatal("expected active entry for pe_classifier")
	}
	if entry.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", entry.Version)
	}

	entry = m.ActiveVersion("nonexistent")
	if entry != nil {
		t.Error("expected nil for nonexistent model")
	}
}

func TestActiveVersion_NoManifest(t *testing.T) {
	m := NewModelManager(nil)
	entry := m.ActiveVersion("pe_classifier")
	if entry != nil {
		t.Error("expected nil when no manifest loaded")
	}
}

func TestModelVersions(t *testing.T) {
	m := NewModelManager(nil)
	m.manifest = &Manifest{
		Models: []ManifestEntry{
			{Name: "pe_classifier", Version: "1.0.0", Status: "active"},
			{Name: "pe_classifier", Version: "0.9.0", Status: "archived"},
			{Name: "behavior_lstm", Version: "1.0.0", Status: "active"},
		},
	}

	versions := m.ModelVersions("pe_classifier")
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions for pe_classifier, got %d", len(versions))
	}

	versions = m.ModelVersions("behavior_lstm")
	if len(versions) != 1 {
		t.Fatalf("expected 1 version for behavior_lstm, got %d", len(versions))
	}

	versions = m.ModelVersions("nonexistent")
	if len(versions) != 0 {
		t.Error("expected 0 versions for nonexistent model")
	}
}

func TestModelVersions_NoManifest(t *testing.T) {
	m := NewModelManager(nil)
	versions := m.ModelVersions("pe_classifier")
	if versions != nil {
		t.Error("expected nil when no manifest loaded")
	}
}

func TestManifestEntry_Metrics(t *testing.T) {
	entry := ManifestEntry{
		Name:    "behavior_lstm",
		Metrics: map[string]float64{"accuracy": 0.95, "f1": 0.93},
	}
	if entry.Metrics["accuracy"] != 0.95 {
		t.Errorf("expected accuracy 0.95, got %f", entry.Metrics["accuracy"])
	}
}
