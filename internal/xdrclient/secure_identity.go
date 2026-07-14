package xdrclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// DeviceIdentity is embedded in the CSR subject / SAN so enrollment and ingest
// can bind the issued certificate to a specific endpoint (IEEE 802.1AR LDevID style).
type DeviceIdentity struct {
	AgentID           string
	Hostname          string
	MachineID         string
	OSFamily          string
	OSVersion         string // arch / version string
	AgentVer          string
	Manufacturer      string
	ProductModel      string
	HardwareSerial    string
	PrimaryIP         string
	Timezone          string
	EnrollTimestamp   string // RFC3339 UTC at CSR generation
	EnrollmentTokenFP string // SHA-256 hex of enrollment token (never the raw token)
}

// GenerateKeyAndCSR creates an agent identity CSR (CN = agentID only).
// Prefer GenerateKeyAndCSRWithIdentity / CollectDeviceIdentity for production.
func GenerateKeyAndCSR(agentID string) (*KeyAndCSR, error) {
	return GenerateKeyAndCSRWithIdentity(DeviceIdentity{AgentID: agentID})
}

// GenerateKeyAndCSRWithIdentity generates an on-device EC P-256 keypair and a
// PKCS#10 CSR embedding device identity (best practice: key never leaves device).
//
// Stable identity (copied into issued cert by Averox RA — 802.1AR / TCG aligned):
//   - Subject CN = agent_id
//   - Subject O  = manufacturer
//   - Subject OU = os_family / product_model
//   - Subject serialNumber = hardware serial (or machine_id)
//   - DNS SAN = hostname
//   - URI SANs = urn:xdr:agent|machine|hw-serial|model|manufacturer|...
//
// Enrollment token: only a SHA-256 fingerprint is embedded (urn:xdr:enrollment-token-fp:...).
// The raw one-time token must never appear in a long-lived certificate.
//
// Volatile context (IP / timezone / timestamp) is also URI-SAN bound for this enroll
// and duplicated in Register labels → PKI tags for console visibility.
func GenerateKeyAndCSRWithIdentity(id DeviceIdentity) (*KeyAndCSR, error) {
	if strings.TrimSpace(id.AgentID) == "" {
		return nil, fmt.Errorf("agent_id required for CSR")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	org := strings.TrimSpace(id.Manufacturer)
	if org == "" {
		org = "xdr-agent"
	}
	serial := strings.TrimSpace(id.HardwareSerial)
	if serial == "" {
		serial = strings.TrimSpace(id.MachineID)
	}

	ou := make([]string, 0, 2)
	if v := strings.TrimSpace(id.OSFamily); v != "" {
		ou = append(ou, v)
	}
	if v := strings.TrimSpace(id.ProductModel); v != "" {
		ou = append(ou, sanitizeDN(v))
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         id.AgentID,
			Organization:       []string{sanitizeDN(org)},
			OrganizationalUnit: ou,
			SerialNumber:       sanitizeDN(serial),
		},
	}
	if host := strings.TrimSpace(id.Hostname); host != "" {
		tmpl.DNSNames = []string{host}
	}

	uris := make([]*url.URL, 0, 12)
	addURI := func(raw string) {
		if u, err := url.Parse(raw); err == nil {
			uris = append(uris, u)
		}
	}
	addURI("urn:xdr:agent:" + id.AgentID)
	if id.MachineID != "" {
		addURI("urn:xdr:machine:" + id.MachineID)
	}
	if id.HardwareSerial != "" {
		addURI("urn:xdr:hw-serial:" + url.PathEscape(id.HardwareSerial))
	}
	if id.ProductModel != "" {
		addURI("urn:xdr:model:" + url.PathEscape(id.ProductModel))
	}
	if id.Manufacturer != "" {
		addURI("urn:xdr:manufacturer:" + url.PathEscape(id.Manufacturer))
	}
	if id.EnrollmentTokenFP != "" {
		// Bind enrollment without leaking the one-time token secret into the cert.
		addURI("urn:xdr:enrollment-token-fp:" + id.EnrollmentTokenFP)
	}
	if id.PrimaryIP != "" {
		addURI("urn:xdr:ip:" + id.PrimaryIP)
	}
	if id.Timezone != "" {
		addURI("urn:xdr:tz:" + url.PathEscape(id.Timezone))
	}
	if id.EnrollTimestamp != "" {
		addURI("urn:xdr:enrolled-at:" + id.EnrollTimestamp)
	}
	if id.AgentVer != "" {
		addURI("urn:xdr:agent-ver:" + url.PathEscape(id.AgentVer))
	}
	tmpl.URIs = uris

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
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

func sanitizeDN(s string) string {
	// Keep DN attributes printable and comma-safe for Subject parsing.
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "-")
	s = strings.ReplaceAll(s, "=", "-")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

const (
	encKeyFileName  = "agent.key.enc"
	encCertFileName = "agent.crt.enc"
	encCSRFileName  = "agent.csr.enc"
	encMagic        = "EDRKEY1"
)

// SealBytes encrypts arbitrary PEM/material with a device-bound AES-256-GCM key.
func SealBytes(plain []byte, dataDir string) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	aesKey := deviceBoundAESKey(dataDir)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plain, nil)
	out := make([]byte, 0, len(encMagic)+len(ct))
	out = append(out, []byte(encMagic)...)
	out = append(out, ct...)
	return out, nil
}

// OpenBytes decrypts a blob produced by SealBytes.
func OpenBytes(sealed []byte, dataDir string) ([]byte, error) {
	if len(sealed) < len(encMagic)+12 {
		return nil, fmt.Errorf("sealed blob too short")
	}
	if string(sealed[:len(encMagic)]) != encMagic {
		return nil, fmt.Errorf("invalid sealed magic")
	}
	ct := sealed[len(encMagic):]
	aesKey := deviceBoundAESKey(dataDir)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		return nil, fmt.Errorf("sealed blob truncated")
	}
	nonce, ciphertext := ct[:nonceSize], ct[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SealPrivateKey encrypts a PEM private key (alias for SealBytes).
func SealPrivateKey(keyPEM []byte, dataDir string) ([]byte, error) {
	return SealBytes(keyPEM, dataDir)
}

// OpenPrivateKey decrypts a sealed private key blob.
func OpenPrivateKey(sealed []byte, dataDir string) ([]byte, error) {
	return OpenBytes(sealed, dataDir)
}

func deviceBoundAESKey(dataDir string) []byte {
	host, _ := os.Hostname()
	material := strings.Join([]string{
		"xdr-agent-identity-key",
		host,
		runtime.GOOS,
		runtime.GOARCH,
		strings.TrimSpace(dataDir),
	}, "|")
	sum := sha256.Sum256([]byte(material))
	return sum[:]
}
