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
	// Merge system roots with every on-disk trust file. Preferring only
	// ingest-ca.pem used to fail when a leftover public CA (e.g. Let's Encrypt)
	// shadowed the Averox chain in ca-chain.pem, and the reverse also failed
	// when ingest was terminated by a public CA. Extra roots do not weaken
	// verification of a correctly chained server cert.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	appended := 0
	for _, p := range ingestTrustFiles(certDir, caPath) {
		caPEM, rerr := os.ReadFile(p)
		if rerr != nil {
			continue
		}
		if pool.AppendCertsFromPEM(caPEM) {
			appended++
		}
	}
	if appended == 0 && caPath != "" {
		return nil, fmt.Errorf("parse trust ca")
	}
	cfg.RootCAs = pool
	return cfg, nil
}

func ingestTrustFiles(certDir, caPath string) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if certDir != "" {
		add(filepath.Join(certDir, "ca-chain.pem"))
		add(filepath.Join(certDir, "ingest-ca.pem"))
		add(filepath.Join(certDir, "ca.pem"))
	}
	add(caPath)
	return out
}
