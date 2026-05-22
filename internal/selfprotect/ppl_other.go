//go:build !windows

package selfprotect

import "fmt"

// PPLPosture captures runtime Protected Process Light state (Windows only).
type PPLPosture struct {
	ProtectionLevel     uint32 `json:"protection_level"`
	LevelName           string `json:"level_name"`
	IsAntimalwarePPL    bool   `json:"is_antimalware_ppl"`
	IsProtected         bool   `json:"is_protected"`
	QueryError          string `json:"query_error,omitempty"`
	AuthenticodeSigned  bool   `json:"authenticode_signed"`
	AuthenticodeSubject string `json:"authenticode_subject,omitempty"`
	AntimalwareEKU      bool   `json:"antimalware_eku"`
	SigningNote         string `json:"signing_prerequisite,omitempty"`
}

// CurrentProtectionLevel is a no-op on non-Windows builds.
func CurrentProtectionLevel() (uint32, error) {
	return 0, fmt.Errorf("PPL not supported on %s", "this platform")
}

// PPLPostureSnapshot returns an empty posture on non-Windows builds.
func PPLPostureSnapshot(exePath string) PPLPosture {
	return PPLPosture{LevelName: "unsupported"}
}

// ValidatePPLRequired is a no-op on non-Windows builds.
func ValidatePPLRequired(required bool, posture PPLPosture) error {
	return nil
}
