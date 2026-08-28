// Package installprogress is a world-readable sidecar the privileged installer
// writes so the attended wizard can animate real steps (not a fake timer).
package installprogress

import (
	"os"
	"path/filepath"
	"strings"
)

const fileName = "edr-install.progress"

// Path is under the OS temp dir so the unprivileged UI can poll while
// osascript / UAC runs the installer as root.
func Path() string {
	return filepath.Join(os.TempDir(), fileName)
}

// Write records the active step id (reqs, pkg, daemon, done, fail).
func Write(step string) {
	step = strings.TrimSpace(step)
	if step == "" {
		return
	}
	_ = os.WriteFile(Path(), []byte(step+"\n"), 0o644)
}

// Read returns the last step id.
func Read() string {
	b, err := os.ReadFile(Path())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Clear removes the sidecar.
func Clear() {
	_ = os.Remove(Path())
}

// Index maps a step id to the installer checklist index (0-based).
func Index(step string, n int) int {
	if n <= 0 {
		return 0
	}
	switch strings.TrimSpace(step) {
	case "reqs":
		return 0
	case "pkg", "copy":
		if n > 1 {
			return 1
		}
		return 0
	case "daemon", "svc", "unit":
		if n > 2 {
			return 2
		}
		return n - 1
	case "done":
		return n
	case "fail":
		return -1
	default:
		return 0
	}
}
