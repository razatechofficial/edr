//go:build !windows

package main

import "go.uber.org/zap"

// applyProcessMitigations is a no-op on non-Windows platforms. The
// matching Windows file enables PROCESS_MITIGATION_* policies; Linux
// and macOS have analogous knobs (prctl(PR_SET_NO_NEW_PRIVS), Hardened
// Runtime) wired via the install scripts rather than at runtime, so
// nothing happens here. The result map keeps the same shape so the
// boot posture writer can serialize uniformly. P2-17.
func applyProcessMitigations(_ *zap.Logger) map[string]any {
	return map[string]any{
		"dynamic_code":    "n/a",
		"image_load":      "n/a",
		"extension_point": "n/a",
		"signature_audit": "n/a",
	}
}
