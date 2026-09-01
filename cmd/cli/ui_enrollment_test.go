package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnrollmentSnapshotFallsBackWhenConfigUnreadable(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"agent_id":"dev-abc","machine_id":"mid-1","ingest_hosts":["ingest.example:443"],"cert_not_after":"2027-08-25T19:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(tls, "enrollment.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(cfg, []byte("agent:\n  data_dir: "+dir+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg, 0o644) })

	enrolled, id, ingest := readEnrollmentSnapshot(cfg, dir)
	if !enrolled || id != "dev-abc" {
		t.Fatalf("enrolled=%v id=%q want true/dev-abc (config may be 0600 root-only)", enrolled, id)
	}
	if ingest != "ingest.example:443" {
		t.Fatalf("ingest=%q", ingest)
	}
	machine, expiry := enrollmentIdentityFrom(cfg, dir)
	if machine != "mid-1" || expiry == "" {
		t.Fatalf("identity machine=%q expiry=%q", machine, expiry)
	}
}

func TestReadEnrollmentSnapshotUsesYamlDataDir(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tls, "enrollment.json"), []byte(`{"agent_id":"from-yaml"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(cfg, []byte("agent:\n  data_dir: "+dir+"\n  id: installer-id\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enrolled, id, _ := readEnrollmentSnapshot(cfg, filepath.Join(dir, "missing"))
	if !enrolled || id != "from-yaml" {
		t.Fatalf("enrolled=%v id=%q", enrolled, id)
	}
}

func TestReadEnrollmentSnapshotMissingJSONIsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(cfg, []byte("agent:\n  data_dir: "+dir+"\n  id: installer-id\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enrolled, id, _ := readEnrollmentSnapshot(cfg, dir)
	if enrolled || id != "" {
		t.Fatalf("installer agent.id must not count as enrolled, got enrolled=%v id=%q", enrolled, id)
	}
}
