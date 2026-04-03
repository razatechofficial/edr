package pidfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.pid")
	if err := Write(path); err != nil {
		t.Fatal(err)
	}
	pid, err := ReadPID(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Fatalf("pid mismatch: got %d want %d", pid, os.Getpid())
	}
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected pid file removed")
	}
}
