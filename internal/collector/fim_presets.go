package collector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
)

const (
	FIMPresetStandard = "standard"
	FIMPresetDefault  = "default"
	FIMPresetCustom   = "custom"
)

// StandardSystemPaths returns OS-critical directories for the standard FIM preset.
func StandardSystemPaths() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/boot"}
	case "darwin":
		return []string{"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	case "windows":
		return []string{
			`C:\Windows\System32`,
			`C:\Windows\SysWOW64`,
			`C:\Windows\System32\drivers\etc`,
		}
	default:
		return nil
	}
}

// PlatformFIMExtras adds agent-specific paths beyond the standard system template.
func PlatformFIMExtras() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "linux":
		out := []string{"/tmp", "/var/tmp"}
		if home != "" {
			out = append(out, home)
		}
		return out
	case "darwin":
		out := []string{
			"/usr/local/bin", "/tmp",
			"/Library/LaunchAgents", "/Library/LaunchDaemons",
			"/Library/Keychains",
			"/Library/Application Support/com.apple.TCC",
		}
		if home != "" {
			out = append(out,
				home,
				filepath.Join(home, "Library/LaunchAgents"),
				filepath.Join(home, "Library/Keychains"),
				filepath.Join(home, "Library/Application Support/com.apple.TCC"),
			)
		}
		return out
	case "windows":
		out := []string{`C:\Windows\Temp`}
		if home != "" {
			out = append(out, home)
		}
		return out
	default:
		if home != "" {
			return []string{home}
		}
		return nil
	}
}

// DefaultFIMIgnorePatterns returns default path suffix ignores for FIM noise reduction.
func DefaultFIMIgnorePatterns() []string {
	return []string{"*.log", "*.swp", "*.swx", "*~"}
}

// ResolveFIMPaths picks FIM watch paths from config.
// Empty fim_paths with preset standard (default) merges system dirs and platform extras.
func ResolveFIMPaths(cfg config.Config) []string {
	if len(cfg.Monitoring.FIMPaths) > 0 {
		return dedupePaths(cfg.Monitoring.FIMPaths)
	}
	preset := strings.ToLower(strings.TrimSpace(cfg.Monitoring.FIMPreset))
	if preset == "" {
		preset = FIMPresetStandard
	}
	switch preset {
	case FIMPresetDefault:
		return dedupePaths(DefaultFIMPaths())
	case FIMPresetCustom:
		return dedupePaths(DefaultFIMPaths())
	case FIMPresetStandard:
		return dedupePaths(append(StandardSystemPaths(), PlatformFIMExtras()...))
	default:
		return dedupePaths(append(StandardSystemPaths(), PlatformFIMExtras()...))
	}
}

// ResolveFIMIgnorePatterns returns ignore globs for fsnotify FIM filtering.
func ResolveFIMIgnorePatterns(cfg config.Config) []string {
	if len(cfg.Monitoring.FIMIgnorePatterns) > 0 {
		return cfg.Monitoring.FIMIgnorePatterns
	}
	return DefaultFIMIgnorePatterns()
}

func dedupePaths(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := filepath.Clean(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

func shouldIgnoreFIMEvent(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
	}
	return false
}
