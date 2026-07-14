// Package keystore provides OS-backed storage for XDR agent identity material
// (private key + signed certificate), preferring platform secure stores:
//
//   - macOS: Keychain (ThisDeviceOnly) when built with CGO
//   - Windows: DPAPI (CryptProtectData) user/machine scope
//   - Linux / fallback: device-bound AES-GCM sealed files
//
// This aligns with NIST SP 800-57 (no plaintext keys) and moves toward
// IEEE 802.1AR / OS keystore practices. TPM-resident non-exportable keys
// remain a future hardening step.
package keystore

import (
	"fmt"
	"strings"
)

const (
	BackendAuto     = "auto"
	BackendKeychain = "keychain"
	BackendDPAPI    = "dpapi"
	BackendFile     = "file"
)

// Material is the agent identity blob set persisted after enrollment.
type Material struct {
	KeyPEM  []byte
	CertPEM []byte
	CSRPEM  []byte // optional audit copy
}

// Store is a platform identity credential backend.
type Store interface {
	// Name returns the backend identifier (keychain|dpapi|file).
	Name() string
	// Save persists key/cert (and optional CSR). Overwrites prior material.
	Save(m Material) error
	// LoadKeyPEM returns the private key PEM (into memory only).
	LoadKeyPEM() ([]byte, error)
	// LoadCertPEM returns the certificate PEM.
	LoadCertPEM() ([]byte, error)
	// LoadCSRPEM returns the CSR if stored.
	LoadCSRPEM() ([]byte, error)
	// Has reports whether key+cert are present.
	Has() bool
}

// Options configures backend selection.
type Options struct {
	// Backend: auto|keychain|dpapi|file (default auto).
	Backend string
	// Dir is the on-disk credential directory (metadata, CA, file backend).
	Dir string
	// DataDir is optional extra bind material for the file backend.
	DataDir string
}

// New selects the best available OS-backed store for this platform.
func New(opt Options) (Store, error) {
	dir := strings.TrimSpace(opt.Dir)
	if dir == "" {
		return nil, fmt.Errorf("keystore: cert dir required")
	}
	backend := strings.ToLower(strings.TrimSpace(opt.Backend))
	if backend == "" {
		backend = BackendAuto
	}

	switch backend {
	case BackendFile:
		return newFileStore(dir, opt.DataDir), nil
	case BackendKeychain:
		s, err := newKeychainStore(dir)
		if err != nil {
			return nil, err
		}
		return s, nil
	case BackendDPAPI:
		s, err := newDPAPIStore(dir)
		if err != nil {
			return nil, err
		}
		return s, nil
	case BackendAuto:
		if s, err := newPlatformStore(dir, opt.DataDir); err == nil && s != nil {
			return s, nil
		}
		return newFileStore(dir, opt.DataDir), nil
	default:
		return nil, fmt.Errorf("keystore: unknown backend %q", backend)
	}
}
