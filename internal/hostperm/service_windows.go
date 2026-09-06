//go:build windows

package hostperm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/razatechofficial/edr/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsServiceName = "EDRAgent"

// EnsureSensorService registers or updates the per-machine EDRAgent service via
// SCM directly. This does not launch edr-agent.exe (CGO/MinGW load failures must
// not block registration during MSI or Start).
func EnsureSensorService(exePath, cfgPath string) error {
	if strings.TrimSpace(exePath) == "" {
		exePath = filepath.Join(platform.InstallDir(), "edr-agent.exe")
	}
	if strings.TrimSpace(cfgPath) == "" {
		cfgPath = filepath.Join(platform.DataDir(), "config.yml")
	}
	absExe, err := filepath.Abs(exePath)
	if err != nil {
		return err
	}
	if st, err := os.Stat(absExe); err != nil || st.IsDir() {
		return fmt.Errorf("sensor binary missing: %s", absExe)
	}
	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(absCfg), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		if scErr := createWithSC(absExe, absCfg); scErr == nil {
			resetServiceStartDACL()
			return nil
		}
		return err
	}
	defer m.Disconnect()

	binLine := quotedServiceBin(absExe, absCfg)
	apply := func(s *mgr.Service) error {
		cfg, cerr := s.Config()
		if cerr != nil {
			return fmt.Errorf("read EDRAgent config: %w", cerr)
		}
		cfg.StartType = mgr.StartAutomatic
		cfg.DelayedAutoStart = false
		cfg.DisplayName = "EDR Agent"
		cfg.Description = "Endpoint Detection and Response Agent"
		cfg.BinaryPathName = binLine
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update EDRAgent: %w", err)
		}
		cfg.DelayedAutoStart = true
		_ = s.UpdateConfig(cfg)
		_ = s.SetRecoveryActions(defaultRecoveryActions(), 86400)
		return nil
	}

	if s, err := m.OpenService(windowsServiceName); err == nil {
		defer s.Close()
		if err := apply(s); err != nil {
			return err
		}
		resetServiceStartDACL()
		return nil
	}

	deadline := time.Now().Add(12 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if s, err := m.OpenService(windowsServiceName); err == nil {
			uerr := apply(s)
			_ = s.Close()
			if uerr == nil {
				resetServiceStartDACL()
				return nil
			}
			last = uerr
		}
		// Do not set DelayedAutoStart or Description on CreateService.
		// x/sys deletes the new service if ChangeServiceConfig2 fails, which
		// leaves EDRAgent missing after MSI and Start on some Server SKUs.
		s, err := m.CreateService(
			windowsServiceName,
			absExe,
			mgr.Config{
				StartType:   mgr.StartAutomatic,
				DisplayName: "EDR Agent",
			},
			"--config", absCfg,
		)
		if err == nil {
			cfg, _ := s.Config()
			cfg.StartType = mgr.StartAutomatic
			cfg.DisplayName = "EDR Agent"
			cfg.Description = "Endpoint Detection and Response Agent"
			cfg.BinaryPathName = binLine
			cfg.DelayedAutoStart = false
			_ = s.UpdateConfig(cfg)
			cfg.DelayedAutoStart = true
			_ = s.UpdateConfig(cfg)
			_ = s.SetRecoveryActions(defaultRecoveryActions(), 86400)
			_ = s.Close()
			resetServiceStartDACL()
			return nil
		}
		last = err
		if !serviceBusyErr(err) {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if scErr := createWithSC(absExe, absCfg); scErr == nil {
		resetServiceStartDACL()
		return nil
	}
	return fmt.Errorf("register EDRAgent: %w", last)
}

func createWithSC(exe, cfg string) error {
	sys := scExe()
	binPath := `"` + exe + `" --config "` + cfg + `"`
	cmd := exec.Command(sys, "create", windowsServiceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "EDR Agent",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err == nil || strings.Contains(strings.ToLower(msg), "already exists") {
		_ = exec.Command(sys, "config", windowsServiceName, "start=", "auto").Run()
		_ = exec.Command(sys, "description", windowsServiceName, "Endpoint Detection and Response Agent").Run()
		return nil
	}
	if msg != "" {
		return fmt.Errorf("sc create: %s", msg)
	}
	return fmt.Errorf("sc create: %w", err)
}

func defaultRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
}

// StartSensorService asks SCM to start EDRAgent. Already running is success.
// Open with START+QUERY only. SERVICE_ALL_ACCESS fails when the service DACL
// denies STOP/DELETE to Everyone (that deny applies to Administrators too).
func StartSensorService() error {
	resetServiceStartDACL()
	s, closer, err := openEDRServiceForStart()
	if err != nil {
		if scErr := startWithSC(); scErr == nil {
			return nil
		}
		return fmt.Errorf("cannot start EDRAgent: %w", err)
	}
	defer closer()
	if st, qerr := s.Query(); qerr == nil {
		switch st.State {
		case svc.Running, svc.StartPending, svc.ContinuePending:
			return nil
		}
	}
	if err := s.Start(); err != nil {
		msg := strings.ToLower(err.Error())
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) ||
			strings.Contains(msg, "already running") ||
			strings.Contains(msg, "already started") {
			return nil
		}
		if scErr := startWithSC(); scErr == nil {
			return nil
		}
		return err
	}
	return nil
}

func openEDRServiceForStart() (*mgr.Service, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	name, err := windows.UTF16PtrFromString(windowsServiceName)
	if err != nil {
		_ = windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	const startRights = windows.SERVICE_START | windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG
	sh, err := windows.OpenService(scm, name, startRights)
	if err != nil {
		_ = windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	return &mgr.Service{Name: windowsServiceName, Handle: sh}, func() {
		_ = windows.CloseServiceHandle(sh)
		_ = windows.CloseServiceHandle(scm)
	}, nil
}

func scExe() string {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe")
	if os.Getenv("SystemRoot") == "" {
		return `C:\Windows\System32\sc.exe`
	}
	return sys
}

// ServiceStartSDDL lets SYSTEM and Administrators start/stop, and the
// interactive console start (RP). There is no Everyone-deny ACE: that deny
// made OpenService(ALL_ACCESS) fail for Administrators and produced a false
// "EDRAgent is not registered (Access is denied.)" on Start.
const ServiceStartSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;IU)"

func resetServiceStartDACL() {
	cmd := exec.Command(scExe(), "sdset", windowsServiceName, ServiceStartSDDL)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	_ = cmd.Run()
}

func startWithSC() error {
	cmd := exec.Command(scExe(), "start", windowsServiceName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	msg := strings.ToLower(strings.TrimSpace(string(out)))
	if err == nil || strings.Contains(msg, "already") {
		return nil
	}
	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("sc start: %s", strings.TrimSpace(string(out)))
	}
	return err
}

func quotedServiceBin(exe, cfg string) string {
	return `"` + exe + `" "--config" "` + cfg + `"`
}

func serviceBusyErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "marked for deletion")
}
