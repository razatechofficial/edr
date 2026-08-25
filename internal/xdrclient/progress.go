package xdrclient

import (
	"os"
	"path/filepath"
	"strings"
)

// EnrollProgressName is the sidecar written while Register runs so a privileged
// GUI/TUI can advance identity steps without streaming osascript output.
const EnrollProgressName = "enroll.progress"

func EnrollProgressPath(dataDir string) string {
	return filepath.Join(dataDir, EnrollProgressName)
}

func WriteEnrollProgress(dataDir, step string) {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(step) == "" {
		return
	}
	_ = os.MkdirAll(dataDir, 0o750)
	_ = os.WriteFile(EnrollProgressPath(dataDir), []byte(strings.TrimSpace(step)+"\n"), 0o600)
}

func ReadEnrollProgress(dataDir string) string {
	b, err := os.ReadFile(EnrollProgressPath(dataDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ClearEnrollProgress(dataDir string) {
	if strings.TrimSpace(dataDir) == "" {
		return
	}
	_ = os.Remove(EnrollProgressPath(dataDir))
}
