package response

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func newTestFileHandler(t *testing.T) (*FileHandler, string) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	qDir := filepath.Join(t.TempDir(), "quarantine")
	h, err := NewFileHandler(logger, qDir, nil)
	if err != nil {
		t.Fatalf("NewFileHandler: %v", err)
	}
	return h, qDir
}

func TestQuarantineFileHandler(t *testing.T) {
	t.Parallel()
	h, _ := newTestFileHandler(t)

	src := filepath.Join(t.TempDir(), "malware.bin")
	os.WriteFile(src, []byte("evil payload"), 0o644)

	result, err := h.Execute(context.Background(), map[string]interface{}{
		"path":   src,
		"reason": "test quarantine",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Success {
		t.Fatalf("Success = false: %s", result.Message)
	}

	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("original file still exists after quarantine")
	}
}

func TestQuarantineFileManifest(t *testing.T) {
	t.Parallel()
	h, qDir := newTestFileHandler(t)

	src := filepath.Join(t.TempDir(), "suspect.exe")
	os.WriteFile(src, []byte("suspect content"), 0o644)

	_, err := h.Execute(context.Background(), map[string]interface{}{
		"path":     src,
		"reason":   "manifest test",
		"alert_id": "ALERT-42",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	manifests, _ := filepath.Glob(filepath.Join(qDir, "*.manifest.json"))
	if len(manifests) == 0 {
		t.Fatal("no manifest file created")
	}

	data, err := os.ReadFile(manifests[0])
	if err != nil {
		t.Fatalf("ReadFile manifest: %v", err)
	}
	var m QuarantineManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal manifest: %v", err)
	}
	if m.OriginalPath != src {
		t.Errorf("OriginalPath = %q, want %q", m.OriginalPath, src)
	}
	if m.AlertID != "ALERT-42" {
		t.Errorf("AlertID = %q, want %q", m.AlertID, "ALERT-42")
	}
	if m.SHA256 == "" {
		t.Error("SHA256 is empty")
	}
}

func TestQuarantineFileRollback(t *testing.T) {
	t.Parallel()
	h, _ := newTestFileHandler(t)

	src := filepath.Join(t.TempDir(), "restore_me.dat")
	original := []byte("precious data")
	os.WriteFile(src, original, 0o644)

	_, err := h.Execute(context.Background(), map[string]interface{}{
		"path":   src,
		"reason": "rollback test",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if err := h.Rollback(context.Background(), map[string]interface{}{
		"path": src,
	}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	restored, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("ReadFile after rollback: %v", err)
	}
	if string(restored) != string(original) {
		t.Errorf("restored content = %q, want %q", restored, original)
	}
}
