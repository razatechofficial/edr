package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestFileHashPoolKnownFileAndCache(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "small.bin")
	payload := []byte("hello-hash-test")
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(want[:])

	base := schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EventType:     schema.EventFile,
		EndpointID:    "e",
		Hostname:      "h",
		OS:            "linux",
	}
	fe := &schema.FileEvent{
		BaseEvent: base,
		Path:      p,
		Operation: "write",
		ActorPID:  1,
	}
	pool := newFileHashPool()
	pool.Submit(fe)
	// WaitForIdle's atomic load pairs with the worker's atomic add to
	// give a race-free view of fe.Hash without the polling loop's
	// data race against the worker goroutine.
	if !pool.WaitForIdle(3 * time.Second) {
		t.Fatal("pool did not drain within 3s")
	}
	if fe.Hash != wantHex {
		t.Fatalf("hash got %q want %q", fe.Hash, wantHex)
	}

	fe2 := &schema.FileEvent{
		BaseEvent: base,
		Path:      p,
		Operation: "write",
		ActorPID:  1,
	}
	pool.Submit(fe2)
	if !pool.WaitForIdle(3 * time.Second) {
		t.Fatal("pool did not drain second submit within 3s")
	}
	if fe2.Hash != wantHex {
		t.Fatalf("second hash got %q want %q (cache)", fe2.Hash, wantHex)
	}
}
