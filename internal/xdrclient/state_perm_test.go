package xdrclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistMetadataWorldReadable(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	store := Store{Dir: tls, DataDir: dir, Backend: "file"}
	if err := store.SaveMetadata(State{AgentID: "a1", MachineID: "m1", IngestHosts: []string{"h:1"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o044 != 0o044 {
		t.Fatalf("enrollment.json should be group/world readable, got %o", perm)
	}
	dinfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dinfo.Mode().Perm()&0o005 != 0o005 {
		t.Fatalf("data dir should be traversable, got %o", dinfo.Mode().Perm())
	}
	tinfo, err := os.Stat(tls)
	if err != nil {
		t.Fatal(err)
	}
	if tinfo.Mode().Perm()&0o005 != 0o005 {
		t.Fatalf("cert dir should be traversable, got %o", tinfo.Mode().Perm())
	}
}

func TestExportDaemonReadableRelaxesFileSidecar(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	store := Store{Dir: tls, DataDir: dir, Backend: "file"}
	if err := store.SaveMetadata(State{AgentID: "a1", MachineID: "m1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.statePath(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ExportDaemonReadable(State{AgentID: "a1"}, []byte("-----BEGIN EC PRIVATE KEY-----\nX\n-----END EC PRIVATE KEY-----\n"), ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o044 != 0o044 {
		t.Fatalf("enrollment.json should stay console-readable, got %o", perm)
	}
}
