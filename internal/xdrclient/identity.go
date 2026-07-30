package xdrclient

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

var uuidRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ResolveMachineID returns a stable host fingerprint used for per-tenant uniqueness.
//
// Priority (industry-aligned: OCSF device.hw_info.uuid / DMTF SMBIOS Type 1 UUID /
// Apple IOPlatformUUID, then serial corroboration, then OS install id):
//  1. Explicit config / XDR_MACHINE_ID (ops override)
//  2. Platform hardware UUID (SMBIOS product_uuid / Win32 UUID / IOPlatformUUID)
//  3. Deterministic hash of manufacturer + hardware serial (when serial is usable)
//  4. OS machine-id (Linux /etc/machine-id — changes on reimage)
//  5. Last-resort host-derived id
func ResolveMachineID(configured string) string {
	if id := normalizeMachineID(configured); id != "" {
		return id
	}
	if id := normalizeMachineID(platformSystemUUID()); id != "" {
		return strings.ToLower(id)
	}
	if id := hardwareSerialFingerprint(); id != "" {
		return id
	}
	if id := normalizeMachineID(osInstallMachineID()); id != "" {
		return id
	}
	return fallbackMachineID()
}

func hardwareSerialFingerprint() string {
	serial := normalizeHardwareValue(readHardwareSerial())
	if serial == "" {
		return ""
	}
	// Avoid treating OS machine-id path fallbacks as "hardware serial".
	if serial == normalizeHardwareValue(osInstallMachineID()) {
		return ""
	}
	mfr := normalizeHardwareValue(readManufacturer())
	if mfr == "" {
		mfr = "unknown"
	}
	sum := sha256.Sum256([]byte(strings.ToLower(mfr) + "|" + strings.ToLower(serial)))
	return "hw-" + hex.EncodeToString(sum[:16])
}

func osInstallMachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	return ""
}

func fallbackMachineID() string {
	if h, err := os.Hostname(); err == nil {
		if host := strings.TrimSpace(h); host != "" {
			return "host-" + strings.ToLower(host)
		}
	}
	return "unknown-machine"
}

func normalizeMachineID(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || !usableHardwareValue(s) {
		return ""
	}
	// Accept bare 32-char hex machine-id / uuid without dashes.
	if uuidRE.MatchString(s) {
		return s
	}
	compact := strings.ReplaceAll(strings.ToLower(s), "-", "")
	if len(compact) == 32 && isHex(compact) {
		// Prefer canonical UUID form when it looks like one.
		return fmt.Sprintf("%s-%s-%s-%s-%s",
			compact[0:8], compact[8:12], compact[12:16], compact[16:20], compact[20:32])
	}
	// Non-UUID ids (config overrides, hashed serials, linux machine-id without dashes).
	if len(s) >= 8 && len(s) <= 128 {
		return s
	}
	return ""
}

func normalizeHardwareValue(raw string) string {
	s := strings.TrimSpace(raw)
	if !usableHardwareValue(s) {
		return ""
	}
	return s
}

func usableHardwareValue(s string) bool {
	if s == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(s))
	switch lower {
	case "none", "null", "n/a", "na", "unknown", "to be filled by o.e.m.",
		"to be filled by oem", "default string", "not specified", "not available",
		"system serial number", "system product name", "system manufacturer":
		return false
	}
	// Reject all-zero / all-F UUIDs commonly returned by VMs/OEM placeholders.
	compact := strings.ReplaceAll(lower, "-", "")
	if compact == strings.Repeat("0", 32) || compact == strings.Repeat("f", 32) {
		return false
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// Hostname returns the OS hostname or "unknown".
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// CertNotAfter parses the leaf certificate NotAfter from PEM.
func CertNotAfter(certPEM string) (time.Time, error) {
	cert, err := ParseLeafCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter.UTC(), nil
}

// ParseLeafCertificate parses the first CERTIFICATE PEM block.
func ParseLeafCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// AgentIDFromCert returns the leaf subject CN (agent_id).
func AgentIDFromCert(certPEM string) (string, error) {
	cert, err := ParseLeafCertificate(certPEM)
	if err != nil {
		return "", err
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		return "", fmt.Errorf("certificate CN missing")
	}
	return cn, nil
}

// MachineIDFromCert returns machine_id from URI SAN urn:xdr:machine:... when present.
func MachineIDFromCert(certPEM string) string {
	cert, err := ParseLeafCertificate(certPEM)
	if err != nil {
		return ""
	}
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		s := u.String()
		const prefix = "urn:xdr:machine:"
		if strings.HasPrefix(s, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(s, prefix))
		}
	}
	return ""
}
