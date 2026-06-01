package rules

import (
	"path/filepath"
	"runtime"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
)

func sigmaHostProduct() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return runtime.GOOS
	}
}

func normalizeSigmaProduct(product string) string {
	p := strings.ToLower(strings.TrimSpace(product))
	switch p {
	case "osx", "darwin", "macos":
		return "macos"
	case "win", "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return p
	}
}

// sigmaPathPlatform returns a non-empty Sigma product when relPath is under
// rules/sigma/{macos,linux,windows}/.
func sigmaPathPlatform(relPath string) string {
	for _, part := range strings.Split(filepath.ToSlash(relPath), "/") {
		switch strings.ToLower(part) {
		case "macos":
			return "macos"
		case "linux":
			return "linux"
		case "windows":
			return "windows"
		}
	}
	return ""
}

func sigmaRuleAppliesToHost(rule sigma.Rule, relPath, hostProduct string) bool {
	host := normalizeSigmaProduct(hostProduct)
	if hint := sigmaPathPlatform(relPath); hint != "" && hint != host {
		return false
	}
	if prod := normalizeSigmaProduct(rule.Logsource.Product); prod != "" && prod != host {
		return false
	}
	return true
}
