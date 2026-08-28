package xdrclient

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/xdrclient/keystore"
)

// ResetLocalIdentity removes device cert, key, agent_id, and ingest sidecars
// so the next Register is a new device. Does not delete rules, models, or config.
func ResetLocalIdentity(dataDir, backend string) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	certDir := ResolveCertDir(config.XDRConfig{}, dataDir)
	for _, b := range []string{keystore.BackendAuto, backend, keystore.BackendFile} {
		b = strings.ToLower(strings.TrimSpace(b))
		if b == "" {
			continue
		}
		ks, err := keystore.New(keystore.Options{
			Backend: b,
			Dir:     certDir,
			DataDir: dataDir,
		})
		if err != nil {
			continue
		}
		if c, ok := ks.(interface{ Clear() error }); ok {
			_ = c.Clear()
		}
	}
	_ = os.RemoveAll(certDir)
	_ = os.Remove(filepath.Join(dataDir, "agent_id"))
	_ = os.RemoveAll(filepath.Join(dataDir, "telemetry-queue"))
	_ = os.RemoveAll(identityStageDir())
	return nil
}
