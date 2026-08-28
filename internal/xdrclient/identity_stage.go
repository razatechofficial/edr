package xdrclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
)

// IdentityStageName is under /tmp so the GUI user and privileged start share it.
// Root cannot read the login Keychain where GUI enroll stored the device cert.
const IdentityStageName = "com.razatech.edr.identity-stage"

func identityStageDir() string {
	return filepath.Join(identityStageRoot, IdentityStageName)
}

var identityStageRoot = "/tmp"

// StageIdentityFromLocalKeystore writes PEMs from this user's OS store into
// /tmp for privileged start. No root required. Files are 0600.
func StageIdentityFromLocalKeystore(cfg config.XDRConfig, dataDir string) error {
	src := Store{
		Dir:     ResolveCertDir(cfg, dataDir),
		DataDir: dataDir,
		Backend: cfg.SecureStorage,
	}
	st, err := src.Load()
	if err != nil {
		if daemonOwnsSealedIdentity(src, err) {
			return nil
		}
		return fmt.Errorf("load device identity: %w", err)
	}
	key, err := src.LoadPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("load device key: %w", err)
	}
	cert, err := src.LoadCertificatePEM()
	if err != nil {
		return fmt.Errorf("load device cert: %w", err)
	}
	if len(cert) > 0 {
		st.CertificatePEM = string(cert)
	}
	csr, _ := src.LoadCSRPEM()
	dir := identityStageDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key"), key, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"), []byte(st.CertificatePEM), 0o600); err != nil {
		return err
	}
	if len(csr) > 0 {
		_ = os.WriteFile(filepath.Join(dir, "agent.csr"), csr, 0o600)
	}
	st.CertificatePEM = ""
	meta, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "enrollment.json"), meta, 0o600)
}

// InstallStagedIdentity seals staged PEMs into the agent cert dir and pins
// yaml to the file backend so the LaunchDaemon can load identity.
func InstallStagedIdentity(cfgPath string, cfg config.XDRConfig, dataDir string) error {
	dir := identityStageDir()
	if _, err := os.Stat(filepath.Join(dir, "agent.key")); err != nil {
		return nil
	}
	key, err := os.ReadFile(filepath.Join(dir, "agent.key"))
	if err != nil {
		return fmt.Errorf("staged identity: %w", err)
	}
	cert, err := os.ReadFile(filepath.Join(dir, "agent.crt"))
	if err != nil {
		return fmt.Errorf("staged identity: %w", err)
	}
	csr, _ := os.ReadFile(filepath.Join(dir, "agent.csr"))
	meta, err := os.ReadFile(filepath.Join(dir, "enrollment.json"))
	if err != nil {
		return fmt.Errorf("staged identity: %w", err)
	}
	var st State
	if err := json.Unmarshal(meta, &st); err != nil {
		return err
	}
	st.CertificatePEM = string(cert)
	store := Store{
		Dir:     ResolveCertDir(cfg, dataDir),
		DataDir: dataDir,
		Backend: "file",
	}
	if err := store.SaveWithCSR(st, key, string(csr)); err != nil {
		return err
	}
	st.SecureStorage = "file"
	if err := EnableIngestFromEnrollment(cfgPath, st); err != nil {
		return err
	}
	_ = os.RemoveAll(dir)
	return nil
}

func daemonOwnsSealedIdentity(s Store, loadErr error) bool {
	if s.Dir == "" || !isPermissionErr(loadErr) {
		return false
	}
	if _, err := os.Stat(s.statePath()); err != nil {
		return false
	}
	st, err := os.Stat(s.encCertPath())
	return err == nil && st.Size() > 0
}

func isPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied")
}
