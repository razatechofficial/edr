//go:build windows

package xdrclient

import (
	"os"
	"path/filepath"
)

func init() {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	identityStageRoot = filepath.Join(pd, "EDR Agent")
}
