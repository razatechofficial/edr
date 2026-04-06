//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/forensics"
	"github.com/razatechofficial/edr/internal/testutil"
	"go.uber.org/zap"
)

func TestForensicsCollectionE2E(t *testing.T) {
	logger := zap.NewNop()
	collector := forensics.NewArtifactCollector(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bundle, err := collector.CollectAll(ctx)
	if err != nil {
		t.Fatalf("CollectAll: %v", err)
	}

	if bundle.Timestamp.IsZero() {
		t.Error("expected non-zero bundle timestamp")
	}
	if bundle.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if bundle.OS == "" {
		t.Error("expected non-empty OS")
	}
	if bundle.Process == nil {
		t.Error("expected process artifacts")
	}
}

func TestChainOfCustodyIntegrity(t *testing.T) {
	hmacKey := []byte("test-hmac-key-for-integration-testing-32b")
	chain := forensics.NewChainOfCustody(hmacKey)

	dir := t.TempDir()
	testFile := testutil.MustCreateTempFile(t, dir, "evidence-*.bin", "sensitive evidence data")

	if err := chain.ForFile(testFile, "collected", "agent-001", "initial evidence collection"); err != nil {
		t.Fatalf("ForFile: %v", err)
	}
	if err := chain.AddEntry("transferred", "agent-001", "forensics-lab", testFile, "abc123", "transferred to lab"); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := chain.AddEntry("analyzed", "analyst-002", "forensics-lab", testFile, "abc123", "malware analysis complete"); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}

	if chain.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", chain.Len())
	}

	if err := chain.Verify(); err != nil {
		t.Fatalf("Verify failed on valid chain: %v", err)
	}

	exported, err := chain.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	var doc struct {
		Entries  []json.RawMessage `json:"entries"`
		ExportTS string            `json:"export_timestamp"`
		HMAC     string            `json:"export_hmac"`
	}
	if err := json.Unmarshal(exported, &doc); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if len(doc.Entries) != 3 {
		t.Errorf("exported entries = %d, want 3", len(doc.Entries))
	}
	if doc.HMAC == "" {
		t.Error("expected non-empty export HMAC")
	}
}

func TestForensicsTimelineFromArtifacts(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		name := filepath.Join(dir, "artifact-"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("data"), 0644); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 artifact files, got %d", len(entries))
	}
}
