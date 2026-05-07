//go:build darwin

package forensics

import (
	"os"
	"path/filepath"
)

func collectTCCDarwin(cfg *ForensicsDeepConfig, bundle *DeepArtifactsBundle) {
	dstDir := filepath.Join(cfg.WorkDir, "tcc")
	systemDB := "/Library/Application Support/com.apple.TCC/TCC.db"
	ent, err := copyFileBounded(systemDB, dstDir, "TCC_system.db", 64<<20)
	if err != nil && ent.Note == "" {
		ent.Note = err.Error()
	}
	if !ent.Copied {
		bundle.TCCDegraded = "system TCC.db not readable (Full Disk Access may be required)"
	}
	bundle.TCC = append(bundle.TCC, ent)

	home, err := os.UserHomeDir()
	if err == nil {
		userDB := filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db")
		ent2, err2 := copyFileBounded(userDB, dstDir, "TCC_user.db", 64<<20)
		if err2 != nil && ent2.Note == "" {
			ent2.Note = err2.Error()
		}
		if !ent2.Copied && bundle.TCCDegraded == "" {
			bundle.TCCDegraded = "user TCC.db not readable"
		}
		bundle.TCC = append(bundle.TCC, ent2)
	} else if bundle.TCCDegraded == "" {
		bundle.TCCDegraded = "user home unavailable: " + err.Error()
	}
}
