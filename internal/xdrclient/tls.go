package xdrclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadClientTLS builds an mTLS client config from enrollment-issued material.
// The private key is loaded from device-bound secure storage into memory only.
func LoadClientTLS(certPath, keyPath, caPath string) (*tls.Config, error) {
	// Legacy path used by renew dial options that only have file paths.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load agent keypair: %w", err)
	}
	return buildTLSConfig(cert, caPath, "")
}

// LoadClientTLSFromStore builds mTLS config using OS-keystore cert + private key.
// The agent presents its Averox-issued device cert; RootCAs verify the ingest
// server (Averox cert_type=server). Prefer cert_dir/ingest-ca.pem when present;
// else fall back to enrollment ca-chain.pem (same PKI).
func LoadClientTLSFromStore(store Store) (*tls.Config, error) {
	certPEM, err := store.LoadCertificatePEM()
	if err != nil {
		return nil, fmt.Errorf("load sealed certificate: %w", err)
	}
	keyPEM, err := store.LoadPrivateKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("load sealed private key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse agent keypair: %w", err)
	}
	return buildTLSConfig(cert, store.CAPath(), store.Dir)
}

// TLSConfigForIngestHost sets ServerName for IP dials (e.g. 127.0.0.1 → localhost).
func TLSConfigForIngestHost(cfg *tls.Config, host string) *tls.Config {
	if cfg == nil {
		return nil
	}
	out := cfg.Clone()
	h := host
	if i := strings.LastIndex(host, ":"); i > 0 {
		h = host[:i]
	}
	h = strings.Trim(h, "[]")
	if h == "127.0.0.1" || h == "::1" {
		out.ServerName = "localhost"
	} else if out.ServerName == "" {
		out.ServerName = h
	}
	return out
}

func buildTLSConfig(cert tls.Certificate, caPath, certDir string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	// Server trust material (verify ingest), not the agent identity CA.
	trustPath := ""
	if certDir != "" {
		p := filepath.Join(certDir, "ingest-ca.pem")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			trustPath = p
		}
	}
	if trustPath == "" {
		trustPath = caPath
	}
	if trustPath != "" {
		caPEM, err := os.ReadFile(trustPath)
		if err != nil {
			return nil, fmt.Errorf("read trust ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse trust ca")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
