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
		return apply(s)
	}

	deadline := time.Now().Add(12 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if s, err := m.OpenService(windowsServiceName); err == nil {
			uerr := apply(s)
			_ = s.Close()
			if uerr == nil {
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
			return nil
		}
		last = err
		if !serviceBusyErr(err) {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if scErr := createWithSC(absExe, absCfg); scErr == nil {
		return nil
	}
	return fmt.Errorf("register EDRAgent: %w", last)
}

func createWithSC(exe, cfg string) error {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe")
	if os.Getenv("SystemRoot") == "" {
		sys = `C:\Windows\System32\sc.exe`
	}
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
func StartSensorService() error {
	m, err := mgr.Connect()
	if err != nil {
		return startWithSC()
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return fmt.Errorf("EDRAgent is not registered: %w", err)
	}
	defer s.Close()
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
		return err
	}
	return nil
}

func startWithSC() error {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe")
	if os.Getenv("SystemRoot") == "" {
		sys = `C:\Windows\System32\sc.exe`
	}
	cmd := exec.Command(sys, "start", windowsServiceName)
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
