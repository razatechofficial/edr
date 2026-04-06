package forensics

import (
	"encoding/json"
	"testing"
)

func TestChainOfCustodyAddVerify(t *testing.T) {
	t.Parallel()

	chain := NewChainOfCustody([]byte("test-key-32-bytes-minimum-secure"))

	entries := []struct {
		action, agentID, hostname, artifactID, sha256, desc string
	}{
		{"collected", "agent-1", "host-a", "art-001", "aaa", "initial collection"},
		{"transferred", "agent-1", "host-b", "art-001", "aaa", "transferred to lab"},
		{"analyzed", "analyst-1", "host-b", "art-001", "aaa", "analysis complete"},
		{"stored", "agent-1", "host-c", "art-001", "aaa", "archived"},
	}

	for _, e := range entries {
		if err := chain.AddEntry(e.action, e.agentID, e.hostname, e.artifactID, e.sha256, e.desc); err != nil {
			t.Fatalf("AddEntry(%s): %v", e.action, err)
		}
	}

	if chain.Len() != len(entries) {
		t.Fatalf("Len() = %d, want %d", chain.Len(), len(entries))
	}

	if err := chain.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestChainOfCustodyTamperDetection(t *testing.T) {
	t.Parallel()

	chain := NewChainOfCustody([]byte("tamper-detection-key-min-32-bytes"))

	for _, action := range []string{"collected", "transferred", "analyzed"} {
		if err := chain.AddEntry(action, "agent", "host", "art", "hash", "desc"); err != nil {
			t.Fatalf("AddEntry: %v", err)
		}
	}

	if err := chain.Verify(); err != nil {
		t.Fatalf("Verify before tamper: %v", err)
	}

	chain.mu.Lock()
	chain.entries[1].Description = "TAMPERED"
	chain.mu.Unlock()

	if err := chain.Verify(); err == nil {
		t.Fatal("Verify should fail after tampering, got nil")
	}
}

func TestChainOfCustodyExport(t *testing.T) {
	t.Parallel()

	chain := NewChainOfCustody([]byte("export-test-key-32-bytes-minimu!"))

	if err := chain.AddEntry("collected", "agent", "host", "artifact-1", "sha256hash", "collected evidence"); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := chain.AddEntry("stored", "agent", "host", "artifact-1", "sha256hash", "stored in vault"); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}

	exported, err := chain.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	var doc struct {
		Entries  []CustodyEntry `json:"entries"`
		ExportTS string         `json:"export_timestamp"`
		HMAC     string         `json:"export_hmac"`
	}
	if err := json.Unmarshal(exported, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Entries) != 2 {
		t.Errorf("entries = %d, want 2", len(doc.Entries))
	}
	if doc.HMAC == "" {
		t.Error("export HMAC should not be empty")
	}
	if doc.ExportTS == "" {
		t.Error("export timestamp should not be empty")
	}
	if doc.Entries[0].Action != "collected" {
		t.Errorf("first entry action = %q, want 'collected'", doc.Entries[0].Action)
	}
	if doc.Entries[0].HMAC == "" {
		t.Error("entry HMAC should not be empty")
	}
}
