// Package xdrclient enrolls the agent with xdr-enrollment and streams OCSF
// telemetry to xdr-ingest over gRPC (TelemetryService/StreamTelemetry).
package xdrclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// KeyAndCSR holds a newly generated EC P-256 key and CSR PEM (CN = agentID).
type KeyAndCSR struct {
	PrivateKey *ecdsa.PrivateKey
	KeyPEM     []byte
	CSRPEM     string
}

// GenerateKeyAndCSR creates an agent identity CSR. Subject CN must be agent_id
// so ingest mTLS can recover AgentIDFromCertificate.
func GenerateKeyAndCSR(agentID string) (*KeyAndCSR, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agent_id required for CSR")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentID},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return &KeyAndCSR{
		PrivateKey: key,
		KeyPEM:     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CSRPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
	}, nil
}
