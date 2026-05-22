package selfprotect

import "strings"

// SCM SERVICE_CONFIG_LAUNCH_PROTECTED values (winnt.h).
const (
	ServiceLaunchProtectedNone               uint32 = 0
	ServiceLaunchProtectedWindows              uint32 = 1
	ServiceLaunchProtectedWindowsLight         uint32 = 2
	ServiceLaunchProtectedAntimalwareLight     uint32 = 3
)

// PROCESS_PROTECTION_LEVEL values returned by ProcessProtectionInformation.
const (
	ProtectionLevelWindows           uint32 = 1
	ProtectionLevelWindowsLight      uint32 = 2
	ProtectionLevelAntimalwareLight  uint32 = 3
)

// ResolveLaunchProtectedTier maps config to an SCM launch-protected level.
// legacyLaunchProtected mirrors monitoring.windows_service_launch_protected.
func ResolveLaunchProtectedTier(tier string, legacyLaunchProtected bool) (level uint32, name string, enabled bool) {
	t := strings.ToLower(strings.TrimSpace(tier))
	if t == "" {
		if legacyLaunchProtected {
			return ServiceLaunchProtectedWindowsLight, "windows_light", true
		}
		return ServiceLaunchProtectedNone, "none", false
	}
	switch t {
	case "none", "off", "false", "0":
		return ServiceLaunchProtectedNone, "none", false
	case "windows", "windows_light", "windows-light", "light":
		return ServiceLaunchProtectedWindowsLight, "windows_light", true
	case "antimalware", "antimalware_light", "antimalware-light", "am-ppl", "ppl":
		return ServiceLaunchProtectedAntimalwareLight, "antimalware_light", true
	default:
		return ServiceLaunchProtectedNone, "none", false
	}
}

// ProtectionLevelName returns a stable label for a protection level DWORD.
func ProtectionLevelName(level uint32) string {
	switch level {
	case ProtectionLevelWindows:
		return "windows"
	case ProtectionLevelWindowsLight:
		return "windows_light"
	case ProtectionLevelAntimalwareLight:
		return "antimalware_light"
	default:
		return "none"
	}
}

// IsAntimalwareProtectionLevel reports AM-PPL (PsProtectedSignerAntimalware-Light).
func IsAntimalwareProtectionLevel(level uint32) bool {
	return level == ProtectionLevelAntimalwareLight
}
