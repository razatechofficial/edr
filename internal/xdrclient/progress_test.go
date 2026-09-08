package xdrclient

import (
	"os"
	"strings"
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

func TestEnrollLastFile(t *testing.T) {
	dir := t.TempDir()
	if ReadEnrollLast(dir) != "" {
		t.Fatal("empty dir")
	}
	WriteEnrollLast(dir, "enrollment register enroll.xdr.averox.com:443: connection refused")
	if got := ReadEnrollLast(dir); !strings.Contains(got, "connection refused") {
		t.Fatalf("got %q", got)
	}
	ClearEnrollLast(dir)
	if got := ReadEnrollLast(dir); got != "" {
		t.Fatalf("cleared %q", got)
	}
}
