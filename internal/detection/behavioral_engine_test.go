package detection

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestBehavioralEngineLoadAndChain(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "behavioral", "chains.yml")
	be, err := NewBehavioralEngine(path, zap.NewNop())
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
		"ppid":        111,
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
	be, err := NewBehavioralEngine(path, zap.NewNop())
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

func TestChain001_ParentPPIDMatchTriggers(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "behavioral", "chains.yml")
	be, err := NewBehavioralEngine(path, zap.NewNop())
	if err != nil {
		t.Fatalf("load chains: %v", err)
	}
	host := "h-chain1"
	evWord := map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": host,
		"Image":       `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		"pid":         100,
		"ppid":        1,
	}
	if be.Process(evWord) != nil {
		t.Fatalf("no alert after first step")
	}
	evCmd := map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": host,
		"Image":       `C:\Windows\System32\cmd.exe`,
		"pid":         200,
		"ppid":        100,
	}
	if d := be.Process(evCmd); len(d) == 0 {
		t.Fatalf("expected CHAIN-001 with ppid=parent pid")
	}
}

func TestChain001_WrongPPIDDoesNotTrigger(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "behavioral", "chains.yml")
	be, err := NewBehavioralEngine(path, zap.NewNop())
	if err != nil {
		t.Fatalf("load chains: %v", err)
	}
	host := "h-chain1b"
	_ = be.Process(map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": host,
		"Image":       `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		"pid":         100,
		"ppid":        1,
	})
	evCmd := map[string]interface{}{
		"event_type":  "process",
		"endpoint_id": host,
		"Image":       `C:\Windows\System32\cmd.exe`,
		"pid":         200,
		"ppid":        999,
	}
	if d := be.Process(evCmd); len(d) > 0 {
		t.Fatalf("expected no CHAIN-001 with wrong ppid, got %d", len(d))
	}
}

func TestBehavioralEvictionRemovesWindow(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "behavioral", "chains.yml")
	be, err := NewBehavioralEngine(path, zap.NewNop())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	be.SetEvictInterval(5 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	be.Start(ctx)
	key := "evict-test-host:CHAIN-001"
	w := &ChainWindow{
		ChainID:   "CHAIN-001",
		HostID:    "evict-test-host",
		StepByID:  make(map[string]interface{}),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	be.mu.Lock()
	be.windows[key] = w
	be.mu.Unlock()
	time.Sleep(25 * time.Millisecond)
	be.mu.Lock()
	_, still := be.windows[key]
	be.mu.Unlock()
	if still {
		t.Fatalf("expired window should be evicted")
	}
}
