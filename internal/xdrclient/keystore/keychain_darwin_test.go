//go:build darwin && cgo

package keystore_test

import (
	"testing"

	"github.com/razatechofficial/edr/internal/xdrclient/keystore"
)

func TestKeychainStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := keystore.New(keystore.Options{Backend: keystore.BackendKeychain, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != keystore.BackendKeychain {
		t.Fatalf("name=%s", s.Name())
	}
	m := keystore.Material{
		KeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nKC\n-----END EC PRIVATE KEY-----\n"),
		CertPEM: []byte("-----BEGIN CERTIFICATE-----\nKC\n-----END CERTIFICATE-----\n"),
		CSRPEM:  []byte("-----BEGIN CERTIFICATE REQUEST-----\nKC\n-----END CERTIFICATE REQUEST-----\n"),
	}
	if err := s.Save(m); err != nil {
		t.Fatal(err)
	}
	if !s.Has() {
		t.Fatal("expected has")
	}
	key, err := s.LoadKeyPEM()
	if err != nil || string(key) != string(m.KeyPEM) {
		t.Fatalf("key mismatch: %v %q", err, key)
	}
	cert, err := s.LoadCertPEM()
	if err != nil || string(cert) != string(m.CertPEM) {
		t.Fatalf("cert mismatch: %v", err)
	}
	csr, err := s.LoadCSRPEM()
	if err != nil || string(csr) != string(m.CSRPEM) {
		t.Fatalf("csr mismatch: %v", err)
	}
}
