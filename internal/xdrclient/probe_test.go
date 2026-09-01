package xdrclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbeLocalEnrollmentReadsJSON(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"agent_id":"dev-abc","machine_id":"mid-1","ingest_hosts":["ingest.example:443"],"cert_not_after":"2027-08-25T19:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(tls, "enrollment.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	got := ProbeLocalEnrollment("", dir)
	if !got.Enrolled || got.AgentID != "dev-abc" || got.MachineID != "mid-1" {
		t.Fatalf("%#v", got)
	}
	if got.Ingest != "ingest.example:443" || got.CertExpiry == "" {
		t.Fatalf("ingest/cert %#v", got)
	}
}

func TestProbeLocalEnrollmentUnreadableJSONStillEnrolled(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(tls, "enrollment.json")
	if err := os.WriteFile(p, []byte(`{"agent_id":"hidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	got := ProbeLocalEnrollment("", dir)
	if !got.Enrolled {
		t.Fatal("present enrollment.json must count as enrolled even when unreadable")
	}
}

func TestProbeLocalEnrollmentSealedCert(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tls, "agent.crt.enc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ProbeLocalEnrollment("", dir)
	if !got.Enrolled {
		t.Fatal("sealed device cert should count as enrolled")
	}
}

func TestProbeLocalEnrollmentEmpty(t *testing.T) {
	dir := t.TempDir()
	got := ProbeLocalEnrollment(filepath.Join(dir, "missing.yaml"), dir)
	if got.Enrolled {
		t.Fatalf("empty data dir must not look enrolled: %#v", got)
	}
}

func TestProbeLocalEnrollmentEmptyTLSDirIsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "xdr-tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := ProbeLocalEnrollment("", dir)
	if got.Enrolled {
		t.Fatalf("empty xdr-tls must not look enrolled: %#v", got)
	}
}

func TestProbeLocalEnrollmentIngestStatus(t *testing.T) {
	dir := t.TempDir()
	tls := filepath.Join(dir, "xdr-tls")
	if err := os.MkdirAll(tls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tls, "ingest.status"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ProbeLocalEnrollment("", dir)
	if !got.Enrolled {
		t.Fatal("ingest.status means the device already enrolled")
	}
}
