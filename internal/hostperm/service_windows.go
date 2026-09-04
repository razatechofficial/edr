//go:build windows

package hostperm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		return err
	}
	defer m.Disconnect()

	binLine := quotedServiceBin(absExe, absCfg)
	if s, err := m.OpenService(windowsServiceName); err == nil {
		defer s.Close()
		_, _ = s.Control(svc.Stop)
		cfg, cerr := s.Config()
		if cerr != nil {
			return fmt.Errorf("read EDRAgent config: %w", cerr)
		}
		cfg.StartType = mgr.StartAutomatic
		cfg.DelayedAutoStart = true
		cfg.DisplayName = "EDR Agent"
		cfg.Description = "Endpoint Detection and Response Agent"
		cfg.BinaryPathName = binLine
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update EDRAgent: %w", err)
		}
		_ = s.SetRecoveryActions(defaultRecoveryActions(), 86400)
		return nil
	}

	var last error
	for i := 0; i < 10; i++ {
		if s, err := m.OpenService(windowsServiceName); err == nil {
			_, _ = s.Control(svc.Stop)
			cfg, cerr := s.Config()
			if cerr == nil {
				cfg.StartType = mgr.StartAutomatic
				cfg.DelayedAutoStart = true
				cfg.DisplayName = "EDR Agent"
				cfg.Description = "Endpoint Detection and Response Agent"
				cfg.BinaryPathName = binLine
				if uerr := s.UpdateConfig(cfg); uerr == nil {
					_ = s.SetRecoveryActions(defaultRecoveryActions(), 86400)
					_ = s.Close()
					return nil
				}
			}
			_ = s.Delete()
			_ = s.Close()
			time.Sleep(500 * time.Millisecond)
		}
		s, err := m.CreateService(
			windowsServiceName,
			absExe,
			mgr.Config{
				StartType:        mgr.StartAutomatic,
				DisplayName:      "EDR Agent",
				Description:      "Endpoint Detection and Response Agent",
				DelayedAutoStart: true,
			},
			"--config", absCfg,
		)
		if err == nil {
			_ = s.SetRecoveryActions(defaultRecoveryActions(), 86400)
			_ = s.Close()
			return nil
		}
		last = err
		if serviceExistsErr(err) {
			for j := 0; j < 40; j++ {
				time.Sleep(500 * time.Millisecond)
				if s, oerr := m.OpenService(windowsServiceName); oerr == nil {
					cfg, cerr := s.Config()
					if cerr == nil {
						cfg.BinaryPathName = binLine
						cfg.StartType = mgr.StartAutomatic
						cfg.DelayedAutoStart = true
						_ = s.UpdateConfig(cfg)
					}
					_ = s.SetRecoveryActions(defaultRecoveryActions(), 86400)
					_ = s.Close()
					return nil
				}
				s2, cerr := m.CreateService(
					windowsServiceName,
					absExe,
					mgr.Config{
						StartType:        mgr.StartAutomatic,
						DisplayName:      "EDR Agent",
						Description:      "Endpoint Detection and Response Agent",
						DelayedAutoStart: true,
					},
					"--config", absCfg,
				)
				if cerr == nil {
					_ = s2.SetRecoveryActions(defaultRecoveryActions(), 86400)
					_ = s2.Close()
					return nil
				}
				last = cerr
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("register EDRAgent: %w", last)
}

func defaultRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
}

func quotedServiceBin(exe, cfg string) string {
	return `"` + exe + `" "--config" "` + cfg + `"`
}

func serviceExistsErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "marked for deletion")
}
