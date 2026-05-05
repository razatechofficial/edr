//go:build windows

package kernel

import (
	"golang.org/x/sys/windows"
)

// WindowsCollectionPosture captures lightweight integrity signals for monitoring_health.json.
func WindowsCollectionPosture() map[string]any {
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	if err != nil {
		return map[string]any{
			"elevated":    false,
			"token_error": err.Error(),
		}
	}
	defer tok.Close()
	return map[string]any{
		"elevated": tok.IsElevated(),
	}
}
