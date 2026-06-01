package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerTLSConfig configures TLS for gRPC and HTTP listeners.
type ServerTLSConfig struct {
	CertPath     string
	KeyPath      string
	ClientCAPath string
	MutualTLS    bool
}

// TLSEnabled reports whether server certificate paths are configured.
func (c ServerTLSConfig) TLSEnabled() bool {
	return c.CertPath != "" && c.KeyPath != ""
}

// Validate checks TLS configuration before listen.
func (c ServerTLSConfig) Validate() error {
	if !c.TLSEnabled() {
		return nil
	}
	if err := fileReadable(c.CertPath); err != nil {
		return fmt.Errorf("controlplane tls cert: %w", err)
	}
	if err := fileReadable(c.KeyPath); err != nil {
		return fmt.Errorf("controlplane tls key: %w", err)
	}
	if c.MutualTLS {
		if c.ClientCAPath == "" {
			return fmt.Errorf("controlplane tls: client CA required when mutual TLS is enabled")
		}
		if err := fileReadable(c.ClientCAPath); err != nil {
			return fmt.Errorf("controlplane tls client CA: %w", err)
		}
	}
	return nil
}

// LoadServerTLS builds a tls.Config for gRPC/HTTP listeners.
func LoadServerTLS(cfg ServerTLSConfig) (*tls.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.TLSEnabled() {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("controlplane tls: load server keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	if cfg.MutualTLS {
		pool, err := loadCertPool(cfg.ClientCAPath)
		if err != nil {
			return nil, err
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = pool
	}

	return tlsCfg, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("controlplane tls: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("controlplane tls: parse client CA")
	}
	return pool, nil
}

func fileReadable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}
