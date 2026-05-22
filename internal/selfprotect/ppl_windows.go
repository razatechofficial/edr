//go:build windows

package selfprotect

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const processProtectionInformation = 61

// PPLPosture captures runtime Protected Process Light state for posture export.
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

type processProtectionLevelInfo struct {
	ProtectionLevel uint32
}

var procNtQueryInformationProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")

// CurrentProtectionLevel reads ProcessProtectionInformation for the current process.
func CurrentProtectionLevel() (uint32, error) {
	var info processProtectionLevelInfo
	var returnLength uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(processProtectionInformation),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if status != 0 {
		return 0, windows.Errno(status)
	}
	return info.ProtectionLevel, nil
}

// PPLPostureSnapshot probes the running process and optional executable signing.
func PPLPostureSnapshot(exePath string) PPLPosture {
	out := PPLPosture{
		SigningNote: "AM-PPL requires Authenticode signing with the Microsoft Antimalware EKU (1.3.6.1.4.1.311.61.4.1) via the MVI attestation pipeline; without it SCM launch-protected=antimalware will fail or the process will not receive AM-PPL.",
	}
	lvl, err := CurrentProtectionLevel()
	if err != nil {
		out.QueryError = err.Error()
		out.LevelName = "unknown"
		return out
	}
	out.ProtectionLevel = lvl
	out.LevelName = ProtectionLevelName(lvl)
	out.IsAntimalwarePPL = IsAntimalwareProtectionLevel(lvl)
	out.IsProtected = lvl >= ProtectionLevelWindowsLight

	if exePath == "" {
		exePath, _ = os.Executable()
	}
	if exePath != "" {
		probe := probeAuthenticode(exePath)
		out.AuthenticodeSigned = probe.Signed
		out.AuthenticodeSubject = probe.Subject
		out.AntimalwareEKU = probe.AntimalwareEKU
	}
	return out
}

// ValidatePPLRequired returns an error when production config requires AM-PPL but the process is not protected.
func ValidatePPLRequired(required bool, posture PPLPosture) error {
	if !required {
		return nil
	}
	if posture.QueryError != "" {
		return fmt.Errorf("windows PPL required but protection query failed: %s", posture.QueryError)
	}
	if !posture.IsAntimalwarePPL {
		return fmt.Errorf("windows AM-PPL required but process protection level is %q (%d); reinstall service with launch_protected_tier=antimalware_light and deploy MVI-signed binary", posture.LevelName, posture.ProtectionLevel)
	}
	if !posture.AuthenticodeSigned {
		return fmt.Errorf("windows AM-PPL required but agent binary is not Authenticode signed")
	}
	if !posture.AntimalwareEKU {
		return fmt.Errorf("windows AM-PPL required but agent binary lacks Microsoft Antimalware Authenticode EKU")
	}
	return nil
}
