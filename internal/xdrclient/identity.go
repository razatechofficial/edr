package xdrclient

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// ResolveMachineID returns a stable host fingerprint.
func ResolveMachineID(configured string) string {
	if id := strings.TrimSpace(configured); id != "" {
		return id
	}
	candidates := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}
	for _, path := range candidates {
		if data, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	if runtime.GOOS == "darwin" {
		// Fallback: hostname is better than empty for local/dev.
		if h, err := os.Hostname(); err == nil && h != "" {
			return "darwin-" + h
		}
	}
	return "unknown-machine"
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
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, fmt.Errorf("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter.UTC(), nil
}
