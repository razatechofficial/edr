package xdrclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadClientTLS builds an mTLS client config from enrollment-issued PEMs.
func LoadClientTLS(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load agent keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read ca chain: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse ca chain")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
