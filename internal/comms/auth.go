package comms

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LoadTLSConfig builds a tls.Config from PEM-encoded certificate, key, and CA
// files. When mutualTLS is true the client certificate is loaded for two-way
// authentication. The returned config enforces TLS 1.2+ and includes
// certificate pinning via a custom VerifyPeerCertificate callback.
func LoadTLSConfig(certPath, keyPath, caPath string, mutualTLS bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("auth: read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("auth: failed to parse CA cert")
		}
		cfg.RootCAs = pool
	}

	if mutualTLS && certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("auth: load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	var pinnedSPKIHash []byte
	if caPath != "" {
		caPEM, _ := os.ReadFile(caPath)
		if block, _ := pem.Decode(caPEM); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				pinnedSPKIHash = h[:]
			}
		}
	}

	if pinnedSPKIHash != nil {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				if equalBytes(h[:], pinnedSPKIHash) {
					return nil
				}
			}
			return fmt.Errorf("auth: certificate public key pin mismatch")
		}
	}

	return cfg, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// CertRotator watches TLS certificate files and reloads them when they change,
// enabling zero-downtime certificate rotation.
type CertRotator struct {
	certPath string
	keyPath  string
	logger   *zap.Logger

	mu   sync.RWMutex
	cert *tls.Certificate

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewCertRotator loads the initial certificate and starts watching for changes.
func NewCertRotator(certPath, keyPath string, logger *zap.Logger) (*CertRotator, error) {
	cr := &CertRotator{
		certPath: certPath,
		keyPath:  keyPath,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}

	if err := cr.reload(); err != nil {
		return nil, err
	}

	go cr.watchLoop()
	return cr, nil
}

// GetCertificate returns the current certificate, suitable for use as a
// tls.Config.GetCertificate callback.
func (cr *CertRotator) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

// GetClientCertificate returns the current certificate for mTLS client auth.
func (cr *CertRotator) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

// Stop terminates the certificate-watching goroutine.
func (cr *CertRotator) Stop() {
	cr.stopOnce.Do(func() {
		close(cr.stopCh)
	})
}

func (cr *CertRotator) reload() error {
	cert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
	if err != nil {
		return fmt.Errorf("cert_rotator: load keypair: %w", err)
	}
	cr.mu.Lock()
	cr.cert = &cert
	cr.mu.Unlock()
	cr.logger.Info("certificate loaded", zap.String("cert", cr.certPath))
	return nil
}

func (cr *CertRotator) watchLoop() {
	var lastHash [sha256.Size]byte
	if data, err := os.ReadFile(cr.certPath); err == nil {
		lastHash = sha256.Sum256(data)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cr.stopCh:
			return
		case <-ticker.C:
			data, err := os.ReadFile(cr.certPath)
			if err != nil {
				continue
			}
			h := sha256.Sum256(data)
			if h != lastHash {
				if err := cr.reload(); err != nil {
					cr.logger.Error("certificate reload failed", zap.Error(err))
					continue
				}
				lastHash = h
			}
		}
	}
}
