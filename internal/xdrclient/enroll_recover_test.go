package xdrclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

func TestRecoverStateFromCredentials(t *testing.T) {
	dir := t.TempDir()
	store := Store{Dir: filepath.Join(dir, "xdr-tls"), DataDir: dir, Backend: "file"}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-recover-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := store.SaveWithCSR(State{
		AgentID:        "agent-recover-1",
		CertificatePEM: string(certPEM),
		IngestHosts:    []string{"127.0.0.1:9020"},
		HeartbeatSec:   30,
	}, keyPEM, ""); err != nil {
		t.Fatal(err)
	}
	// Simulate /tmp wipe of enrollment.json only.
	if err := os.Remove(store.statePath()); err != nil {
		t.Fatal(err)
	}

	cfg := config.XDRConfig{
		EnrollmentHost: "127.0.0.1:50051",
		IngestHosts:    []string{"127.0.0.1:9020"},
		SecureStorage:  "file",
		CertDir:        store.Dir,
	}
	res, err := EnsureEnrolled(context.Background(), EnrollOptions{
		Config:  cfg,
		AgentID: "ignored-when-cert-cn-present",
		DataDir: dir,
		Force:   false,
	})
	if err != nil {
		t.Fatalf("EnsureEnrolled: %v", err)
	}
	if res.Fresh {
		t.Fatal("expected resume, not fresh Register")
	}
	if res.State.AgentID != "agent-recover-1" {
		t.Fatalf("agent_id=%s", res.State.AgentID)
	}
	if len(res.State.IngestHosts) == 0 {
		t.Fatal("missing ingest_hosts")
	}
}
