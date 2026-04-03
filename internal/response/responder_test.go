package response

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestKillSelfBlocked(t *testing.T) {
	r := NewResponder(true, []string{"systemd"})
	res := r.Execute(schema.ResponseCommand{
		Action:     schema.ResponseKillProcess,
		ProcessPID: os.Getpid(),
	})
	if res.Success {
		t.Fatal("expected self kill to be blocked")
	}
}

func TestQuarantineFile(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWd) }()

	src := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	res := quarantineFile(schema.ResponseCommand{
		Action:   schema.ResponseQuarantine,
		FilePath: src,
	})
	if !res.Success {
		t.Fatalf("expected quarantine success, got: %s", res.Message)
	}
}
