package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLoadServerTLSMutual(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := writeTestCert(t, dir, "ca.crt", "ca.key", true, "")
	serverCert, serverKey := writeTestCert(t, dir, "server.crt", "server.key", false, caCert)
	clientCert, clientKey := writeTestCert(t, dir, "client.crt", "client.key", false, caCert)

	cfg := ServerTLSConfig{
		CertPath:     serverCert,
		KeyPath:      serverKey,
		ClientCAPath: caCert,
		MutualTLS:    true,
	}
	tlsCfg, err := LoadServerTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v", tlsCfg.ClientAuth)
	}

	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      mustPool(t, caCert),
		Certificates: []tls.Certificate{mustKeyPair(t, clientCert, clientKey)},
	}
	_ = caKey
	_ = clientTLS
}

func TestLoadServerTLSOneWay(t *testing.T) {
	dir := t.TempDir()
	caCert, _ := writeTestCert(t, dir, "ca.crt", "ca.key", true, "")
	serverCert, serverKey := writeTestCert(t, dir, "server.crt", "server.key", false, caCert)

	cfg := ServerTLSConfig{
		CertPath:  serverCert,
		KeyPath:   serverKey,
		MutualTLS: false,
	}
	tlsCfg, err := LoadServerTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v", tlsCfg.ClientAuth)
	}
	_ = serverKey
}

func TestServerTLSValidateRequiresClientCAForMutual(t *testing.T) {
	dir := t.TempDir()
	serverCert, serverKey := writeTestCert(t, dir, "server.crt", "server.key", true, "")
	cfg := ServerTLSConfig{
		CertPath:  serverCert,
		KeyPath:   serverKey,
		MutualTLS: true,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error without client CA")
	}
	_ = serverKey
}

func mustPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("parse CA")
	}
	return pool
}

func mustKeyPair(t *testing.T, certPath, keyPath string) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeTestCert(t *testing.T, dir, certName, keyName string, isCA bool, signWith string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, certName)
	keyPath = filepath.Join(dir, keyName)
	// Reuse comms test helper pattern via openssl subprocess when available.
	if _, err := os.Stat("/usr/bin/openssl"); err == nil {
		if isCA {
			runOpenSSL(t, dir, "genrsa", "-out", keyPath, "2048")
			runOpenSSL(t, dir, "req", "-x509", "-new", "-nodes", "-key", keyPath,
				"-subj", "/CN=edr-test-ca", "-days", "1", "-out", certPath)
			return certPath, keyPath
		}
		runOpenSSL(t, dir, "genrsa", "-out", keyPath, "2048")
		runOpenSSL(t, dir, "req", "-new", "-key", keyPath, "-subj", "/CN=edr-test", "-out", filepath.Join(dir, "req.csr"))
		runOpenSSL(t, dir, "x509", "-req", "-in", filepath.Join(dir, "req.csr"),
			"-CA", signWith, "-CAkey", filepath.Join(dir, "ca.key"), "-CAcreateserial",
			"-out", certPath, "-days", "1")
		return certPath, keyPath
	}
	t.Skip("openssl not available")
	return "", ""
}

func runOpenSSL(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("openssl", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
}
