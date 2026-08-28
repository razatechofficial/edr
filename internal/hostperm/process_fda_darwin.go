//go:build darwin

package hostperm

import (
	"os"
	"path/filepath"
)

// ProcessHasFDA is true when this process can open a Full Disk Access path.
func ProcessHasFDA() bool {
	paths := []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"/var/db/locationd/clients.plist",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, "Library/Safari/Bookmarks.plist"),
			filepath.Join(home, "Library/Mail"),
			filepath.Join(home, "Library/Calendars"),
		)
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err == nil {
			_ = f.Close()
			return true
		}
		if _, err := os.ReadDir(p); err == nil {
			return true
		}
	}
	return false
}
