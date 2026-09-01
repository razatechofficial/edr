package xdrclient

import (
	"os"
	"testing"
)

func TestEnrollProgressFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(PublicEnrollProgressPath(), []byte("\n"), 0o666)
	t.Cleanup(func() { _ = os.Remove(PublicEnrollProgressPath()) })
	if ReadEnrollProgress(dir) != "" {
		t.Fatal("empty dir")
	}
	WriteEnrollProgress(dir, "csr")
	if got := ReadEnrollProgress(dir); got != "csr" {
		t.Fatalf("got %q", got)
	}
	if got := readProgressFile(PublicEnrollProgressPath()); got != "csr" {
		t.Fatalf("public %q", got)
	}
	ClearEnrollProgress(dir)
	if got := ReadEnrollProgress(dir); got != "" {
		t.Fatalf("cleared %q", got)
	}
}
