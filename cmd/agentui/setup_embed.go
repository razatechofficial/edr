//go:build embedsetup

package main

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Populated at compile time from cmd/agentui/payload/installer.bin
// (see scripts/ci/stage_embedded_installer.sh + build_windows_binaries.sh).
//
//go:embed payload/installer.bin
var embeddedInstallerBin []byte

var (
	setupOnce sync.Once
	setupPath string
)

func setupPayloadDir() string {
	// Never write the payload under the user profile on Windows. Defender
	// treats %LOCALAPPDATA%\…\exe + elevated run as a dropper.
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "EDR", "setup")
		}
		return `C:\ProgramData\EDR\setup`
	}
	if d, err := os.UserCacheDir(); err == nil && d != "" {
		return filepath.Join(d, "EDR", "setup")
	}
	return filepath.Join(os.TempDir(), "edr-setup")
}

func embeddedSetupInstallerPath() string {
	setupOnce.Do(func() {
		if len(embeddedInstallerBin) == 0 {
			return
		}
		dir := setupPayloadDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return
		}
		name := "edr-installer"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		out := filepath.Join(dir, name)
		if st, err := os.Stat(out); err == nil && st.Size() == int64(len(embeddedInstallerBin)) {
			setupPath = out
			return
		}
		tmp := out + ".tmp"
		if err := os.WriteFile(tmp, embeddedInstallerBin, 0o755); err != nil {
			return
		}
		if err := os.Rename(tmp, out); err != nil {
			_ = os.Remove(tmp)
			return
		}
		_ = os.Chmod(out, 0o755)
		setupPath = out
	})
	return setupPath
}
