//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/selfprotect"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func serviceHardeningPosturePath() string {
	return filepath.Join(WindowsDataRoot(), "service_hardening_posture.json")
}

// SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT (0x2) — SCM launch protection tier (legacy generic PPL).
const serviceLaunchProtectedWindowsLight = 0x00000002

// SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT (0x3) — AM-PPL service launch tier.
const serviceLaunchProtectedAntimalwareLight = 0x00000003

// serviceRequiredPrivilegesInfo mirrors SERVICE_REQUIRED_PRIVILEGES_INFO.
type serviceRequiredPrivilegesInfo struct {
	PmszRequiredPrivileges *uint16
}

// serviceLaunchProtectedInfo mirrors SERVICE_LAUNCH_PROTECTED_INFO.
type serviceLaunchProtectedInfo struct {
	DwLaunchProtected uint32
}

const daclSecurityInformation = 0x00000004

var (
	advapi32Svc                   = windows.NewLazySystemDLL("advapi32.dll")
	kernel32Svc                   = windows.NewLazySystemDLL("kernel32.dll")
	procConvertSDDLToSD           = advapi32Svc.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetServiceObjectSecurityW = advapi32Svc.NewProc("SetServiceObjectSecurity")
	procLocalFreeSvc              = kernel32Svc.NewProc("LocalFree")
)

func utf16MultiSZ(lines []string) (*uint16, error) {
	if len(lines) == 0 {
		z := []uint16{0}
		return &z[0], nil
	}
	var buf []uint16
	for _, line := range lines {
		u, err := windows.UTF16FromString(line)
		if err != nil {
			return nil, err
		}
		if len(u) < 2 {
			continue
		}
		// UTF16FromString includes a trailing NUL; keep internal NULs between strings.
		buf = append(buf, u[:len(u)-1]...)
		buf = append(buf, 0)
	}
	buf = append(buf, 0)
	out := make([]uint16, len(buf))
	copy(out, buf)
	return &out[0], nil
}

func setServiceRequiredPrivileges(h windows.Handle) error {
	multi, err := utf16MultiSZ([]string{
		"SeChangeNotifyPrivilege",
		"SeImpersonatePrivilege",
		"SeAuditPrivilege",
		"SeAssignPrimaryTokenPrivilege",
	})
	if err != nil {
		return err
	}
	info := serviceRequiredPrivilegesInfo{PmszRequiredPrivileges: multi}
	return windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info)))
}

func setServiceLaunchProtected(h windows.Handle, level uint32) error {
	info := serviceLaunchProtectedInfo{DwLaunchProtected: level}
	return windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_LAUNCH_PROTECTED, (*byte)(unsafe.Pointer(&info)))
}

func setServiceObjectDACL(h windows.Handle) error {
	// Deny SERVICE_STOP(SW) + DELETE(SD) to Everyone, keep full access for SYSTEM/Administrators.
	// SDDL is applied only when explicitly enabled by config.
	sddl := "D:(D;;SWSD;;;WD)(A;;KA;;;SY)(A;;KA;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
	sddlPtr, err := windows.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var sd uintptr
	r1, _, e1 := procConvertSDDLToSD.Call(
		uintptr(unsafe.Pointer(sddlPtr)),
		uintptr(1),
		uintptr(unsafe.Pointer(&sd)),
		0,
	)
	if r1 == 0 {
		if e1 != nil && e1 != windows.ERROR_SUCCESS {
			return e1
		}
		return fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")
	}
	defer procLocalFreeSvc.Call(sd)
	r2, _, e2 := procSetServiceObjectSecurityW.Call(
		uintptr(h),
		uintptr(daclSecurityInformation),
		sd,
	)
	if r2 == 0 {
		if e2 != nil && e2 != windows.ERROR_SUCCESS {
			return e2
		}
		return fmt.Errorf("SetServiceObjectSecurity failed")
	}
	return nil
}

func applyWindowsServiceHardening(s *mgr.Service, exePath string, c config.Config) map[string]any {
	out := map[string]any{
		"applied":                    false,
		"failure_actions_configured": false,
		"install_dir_acl_attempted":  false,
		"required_privileges_set":    false,
		"service_dacl_hardened":      false,
		"launch_protected_tier":      "none",
	}
	if s == nil {
		out["reason"] = "nil_service"
		return out
	}
	if !c.Monitoring.WindowsServiceHardening {
		out["reason"] = "disabled_by_config"
		return out
	}
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, 86400); err != nil {
		out["failure_actions_error"] = err.Error()
		return out
	}
	out["failure_actions_configured"] = true
	out["applied"] = true

	cur, cerr := s.Config()
	if cerr != nil {
		out["config_read_error"] = cerr.Error()
	} else {
		cur.SidType = windows.SERVICE_SID_TYPE_RESTRICTED
		if uerr := s.UpdateConfig(cur); uerr != nil {
			out["service_sid_error"] = uerr.Error()
		} else {
			out["service_sid_type"] = "restricted"
		}
	}

	if perr := setServiceRequiredPrivileges(s.Handle); perr != nil {
		out["required_privileges_error"] = perr.Error()
	} else {
		out["required_privileges_set"] = true
	}

	launchLevel, launchTier, launchEnabled := selfprotect.ResolveLaunchProtectedTier(
		c.Monitoring.WindowsServiceLaunchProtectedTier,
		c.Monitoring.WindowsServiceLaunchProtected,
	)
	out["launch_protected_tier"] = launchTier
	out["wdm_protect_device"] = `\\.\EdrProtect`
	out["wdm_protect_inf"] = "platform/windows/driver/edr_protect.inf"
	out["elam_inf"] = "platform/windows/elam/edr_elam.inf"
	out["signing_pipeline"] = "platform/windows/signing/pipeline.json"
	if launchEnabled {
		if lerr := setServiceLaunchProtected(s.Handle, launchLevel); lerr != nil {
			out["launch_protected_error"] = lerr.Error()
		} else {
			out["launch_protected"] = launchTier
			out["launch_protected_scm_level"] = launchLevel
		}
	}

	exePathForPPL := exePath
	if exePathForPPL == "" {
		exePathForPPL, _ = os.Executable()
	}
	ppl := selfprotect.PPLPostureSnapshot(exePathForPPL)
	out["ppl_runtime_level"] = ppl.ProtectionLevel
	out["ppl_runtime_level_name"] = ppl.LevelName
	out["ppl_is_antimalware"] = ppl.IsAntimalwarePPL
	out["authenticode_signed"] = ppl.AuthenticodeSigned
	out["antimalware_eku"] = ppl.AntimalwareEKU
	if ppl.AuthenticodeSubject != "" {
		out["authenticode_subject"] = ppl.AuthenticodeSubject
	}
	if ppl.SigningNote != "" {
		out["signing_prerequisite"] = ppl.SigningNote
	}
	if launchTier == "antimalware_light" && !ppl.AntimalwareEKU {
		out["signing_action_required"] = "Deploy binary signed with Microsoft Antimalware Authenticode EKU (MVI attestation) before AM-PPL can activate"
	}

	if c.Monitoring.WindowsServiceHardeningACL {
		dir := filepath.Dir(exePath)
		out["install_dir_acl_attempted"] = true
		if err := hardenServiceInstallDirACL(dir); err != nil {
			out["install_dir_acl_error"] = err.Error()
		} else {
			out["install_dir_acl_ok"] = true
		}
	}
	if c.Monitoring.WindowsServiceDaclHardened {
		if derr := setServiceObjectDACL(s.Handle); derr != nil {
			out["service_dacl_error"] = derr.Error()
		} else {
			out["service_dacl_hardened"] = true
		}
	}
	return out
}

func restrictSensitiveTree(dir string) {
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o700)
	cmd := exec.Command("icacls", dir,
		"/inheritance:r",
		"/grant:r", "SYSTEM:(OI)(CI)F",
		"/grant:r", "Administrators:(OI)(CI)F",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}

func hardenServiceInstallDirACL(dir string) error {
	if dir == "" || dir == "." {
		return fmt.Errorf("empty install dir")
	}
	// SYSTEM + Administrators keep full control. Users get RX only: unelevated
	// Explorer (UAC split token) is not in Administrators, so without RX the
	// Start Menu shortcut fails with "cannot be accessed / permissions".
	cmd := exec.Command("icacls", dir,
		"/inheritance:r",
		"/grant:r", "SYSTEM:(OI)(CI)F",
		"/grant:r", "Administrators:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-545:(OI)(CI)RX",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func writeServiceHardeningPosture(m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(serviceHardeningPosturePath()), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(serviceHardeningPosturePath(), b, 0o644)
}
