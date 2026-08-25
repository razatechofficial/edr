package xdrclient

import (
	"os"
	"testing"
)

func TestEnrollProgressFile(t *testing.T) {
	dir := t.TempDir()
	if ReadEnrollProgress(dir) != "" {
		t.Fatal("empty dir")
	}
	WriteEnrollProgress(dir, "csr")
	if got := ReadEnrollProgress(dir); got != "csr" {
		t.Fatalf("got %q", got)
	}
	ClearEnrollProgress(dir)
	if _, err := os.Stat(EnrollProgressPath(dir)); !os.IsNotExist(err) {
		t.Fatal("expected removed")
	}
}
