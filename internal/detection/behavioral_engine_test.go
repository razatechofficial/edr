package detection

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBehavioralEngineLoadAndChain(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "behavioral", "chains.yml")
	be, err := NewBehavioralEngine(path)
	if err != nil {
		t.Fatalf("load chains: %v", err)
	}
	if len(be.chains) < 6 {
		t.Fatalf("expected at least 6 chains, got %d", len(be.chains))
	}

	ev1 := map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": "h1",
		"Image":       `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		"pid":         111,
	}
	ev2 := map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": "h1",
		"Image":       `C:\Windows\System32\cmd.exe`,
		"pid":         222,
	}
	if got := be.Process(ev1); len(got) != 0 {
		t.Fatalf("unexpected detection after first step: %d", len(got))
	}
	got := be.Process(ev2)
	if len(got) == 0 {
		t.Fatalf("expected chain detection")
	}
}

func TestBehavioralEngineThreshold(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "behavioral", "chains.yml")
	be, err := NewBehavioralEngine(path)
	if err != nil {
		t.Fatalf("load chains: %v", err)
	}
	base := map[string]interface{}{
		"event_type":  "file",
		"endpoint_id": "h2",
		"operation":   "rename",
		"pid":         1,
	}
	found := false
	for i := 0; i < 21; i++ {
		if len(be.Process(base)) > 0 {
			found = true
		}
		time.Sleep(1 * time.Millisecond)
	}
	if !found {
		t.Fatalf("expected ransomware threshold detection")
	}
}
