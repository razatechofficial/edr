package xdrclient

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// EnrollProgressName is the sidecar written while Register runs so a privileged
// GUI/TUI can advance identity steps without streaming osascript output.
const EnrollProgressName = "enroll.progress"

const publicEnrollProgressName = "com.razatech.edr.enroll.progress"

func EnrollProgressPath(dataDir string) string {
	return filepath.Join(dataDir, EnrollProgressName)
}

// PublicEnrollProgressPath is world-readable so the GUI user can poll steps
// while enroll runs as root (DataDir files are often 0600).
func PublicEnrollProgressPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), publicEnrollProgressName)
	}
	return "/tmp/" + publicEnrollProgressName
}

func writeProgressFile(path, step string, mode os.FileMode) {
	_ = os.WriteFile(path, []byte(strings.TrimSpace(step)+"\n"), mode)
	_ = os.Chmod(path, mode)
}

func WriteEnrollProgress(dataDir, step string) {
	step = strings.TrimSpace(step)
	if step == "" {
		return
	}
	if strings.TrimSpace(dataDir) != "" {
		_ = os.MkdirAll(dataDir, 0o755)
		writeProgressFile(EnrollProgressPath(dataDir), step, 0o644)
	}
	writeProgressFile(PublicEnrollProgressPath(), step, 0o666)
}

func readProgressFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ReadEnrollProgress(dataDir string) string {
	if s := readProgressFile(EnrollProgressPath(dataDir)); s != "" {
		return s
	}
	return readProgressFile(PublicEnrollProgressPath())
}

func ClearEnrollProgress(dataDir string) {
	if strings.TrimSpace(dataDir) != "" {
		_ = os.Remove(EnrollProgressPath(dataDir))
	}
	pub := PublicEnrollProgressPath()
	if err := os.Remove(pub); err != nil {
		_ = os.WriteFile(pub, []byte("\n"), 0o666)
		_ = os.Chmod(pub, 0o666)
	}
}
