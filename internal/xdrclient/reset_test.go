package xdrclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResetLocalIdentityRemovesCertDirAndAgentID(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(cert, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent_id"), []byte("old-id\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cert, "enrollment.json"), []byte(`{"agent_id":"old-id"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(dir, "telemetry-queue")
	if err := os.MkdirAll(q, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(q, "x.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ResetLocalIdentity(dir, "file"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent_id")); !os.IsNotExist(err) {
		t.Fatalf("agent_id still present: %v", err)
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatalf("xdr-tls still present: %v", err)
	}
	if _, err := os.Stat(q); !os.IsNotExist(err) {
		t.Fatalf("telemetry-queue still present: %v", err)
	}
}
