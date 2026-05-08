package collector

import (
	"path/filepath"
	"strings"
)

func normalizeWinPath(s string) string {
	return strings.ToLower(filepath.Clean(strings.TrimSpace(s)))
}

func trustedWinPath(p, sysRoot, progFiles string) bool {
	if sysRoot != "" && strings.HasPrefix(p, sysRoot+`\`) {
		return true
	}
	if progFiles != "" && strings.HasPrefix(p, progFiles+`\`) {
		return true
	}
	return false
}
