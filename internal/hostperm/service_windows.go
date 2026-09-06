//go:build windows

package hostperm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/platform"
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
	apply := func(s *mgr.Service) error {
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

	// Do not Control(Stop) here: a wedged START_PENDING service blocks MSI
	// and the operator window for a long time. binPath can be updated live.
	if s, err := m.OpenService(windowsServiceName); err == nil {
		defer s.Close()
		return apply(s)
	}

	deadline := time.Now().Add(8 * time.Second)
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
		time.Sleep(250 * time.Millisecond)
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
