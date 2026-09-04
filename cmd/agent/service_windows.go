//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

func serviceAlreadyPresent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "marked for deletion")
}

func installLog(format string, args ...any) {
	p := filepath.Join(WindowsDataRoot(), "logs", "install.log")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", args...)
}

func quotedBinPath(exe string, extra ...string) string {
	parts := []string{`"` + exe + `"`}
	for _, a := range extra {
		parts = append(parts, `"`+a+`"`)
	}
	return strings.Join(parts, " ")
}

func openOrCreateService(m *mgr.Mgr, exePath, cfgPath string) (*mgr.Service, error) {
	if existing, err := m.OpenService(windowsServiceName); err == nil {
		_, _ = existing.Control(svc.Stop)
		cfg, cerr := existing.Config()
		if cerr == nil {
			cfg.StartType = mgr.StartAutomatic
			cfg.DelayedAutoStart = true
			cfg.DisplayName = "EDR Agent"
			cfg.Description = "Endpoint Detection and Response Agent"
			cfg.BinaryPathName = quotedBinPath(exePath, "--config", cfgPath)
			if uerr := existing.UpdateConfig(cfg); uerr != nil {
				installLog("UpdateConfig existing service: %v", uerr)
			}
		}
		return existing, nil
	}

	var last error
	// MSI deferred --install can race AV locks and a prior sc delete (marked for
	// deletion). Retry longer than a typical MSI custom-action patience window.
	for i := 0; i < 8; i++ {
		if existing, err := m.OpenService(windowsServiceName); err == nil {
			// Prefer update-in-place. Only delete when we must recreate.
			cfg, cerr := existing.Config()
			if cerr == nil {
				cfg.StartType = mgr.StartAutomatic
				cfg.DelayedAutoStart = true
				cfg.DisplayName = "EDR Agent"
				cfg.Description = "Endpoint Detection and Response Agent"
				cfg.BinaryPathName = quotedBinPath(exePath, "--config", cfgPath)
				if uerr := existing.UpdateConfig(cfg); uerr != nil {
					installLog("UpdateConfig before recreate: %v", uerr)
				} else {
					return existing, nil
				}
			}
			_, _ = existing.Control(svc.Stop)
			_ = existing.Delete()
			_ = existing.Close()
			time.Sleep(500 * time.Millisecond)
		}
		s, err := m.CreateService(
			windowsServiceName,
			exePath,
			mgr.Config{
				StartType:        mgr.StartAutomatic,
				DisplayName:      "EDR Agent",
				Description:      "Endpoint Detection and Response Agent",
				DelayedAutoStart: true,
			},
			"--config", cfgPath,
		)
		if err == nil {
			return s, nil
		}
		last = err
		installLog("CreateService attempt %d: %v", i+1, err)
		if serviceAlreadyPresent(err) {
			// Marked-for-delete clears only after all handles close; wait it out.
			for j := 0; j < 30; j++ {
				time.Sleep(500 * time.Millisecond)
				if existing, oerr := m.OpenService(windowsServiceName); oerr == nil {
					return existing, nil
				}
				s2, cerr := m.CreateService(
					windowsServiceName,
					exePath,
					mgr.Config{
						StartType:        mgr.StartAutomatic,
						DisplayName:      "EDR Agent",
						Description:      "Endpoint Detection and Response Agent",
						DelayedAutoStart: true,
					},
					"--config", cfgPath,
				)
				if cerr == nil {
					return s2, nil
				}
				last = cerr
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	if existing, err := m.OpenService(windowsServiceName); err == nil {
		return existing, nil
	}
	installLog("CreateService exhausted: %v", last)
	return nil, fmt.Errorf("register EDRAgent failed (if marked for deletion, reboot then reinstall): %w", last)
}

func installService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	cfgPath := WindowsConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(WindowsDataRoot(), 0o755); err != nil {
		return fmt.Errorf("create data root: %w", err)
	}
	installLog("install start exe=%s config=%s", exePath, cfgPath)

	s, err := openOrCreateService(m, exePath, cfgPath)
	if err != nil {
		installLog("create service: %v", err)
		return fmt.Errorf("register EDRAgent service: %w", err)
	}
	defer s.Close()

	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	_ = s.SetRecoveryActions(actions, 86400)

	restrictSensitiveTree(WindowsDataRoot())
	restrictSensitiveTree(filepath.Join(WindowsDataRoot(), "rules"))
	restrictSensitiveTree(filepath.Join(WindowsDataRoot(), "models"))
	restrictSensitiveTree(filepath.Join(WindowsDataRoot(), "logs"))
	restrictSensitiveTree(filepath.Join(WindowsDataRoot(), "xdr-tls"))

	_ = eventlog.Remove(windowsServiceName)
	if err := eventlog.InstallAsEventCreate(windowsServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		installLog("eventlog source: %v (continuing)", err)
	}

	var posture map[string]any
	if c, err := config.Load(cfgPath); err == nil {
		posture = applyWindowsServiceHardening(s, exePath, c)
	} else {
		posture = map[string]any{"applied": false, "reason": "config_unavailable", "error": err.Error()}
	}
	_ = writeServiceHardeningPosture(posture)
	if err := installWindowsControlPlaneIntent(); err != nil {
		installLog("control plane intent: %v (continuing)", err)
	}
	// Do not start the sensor during MSI. Starting loads models and can hang setup;
	// the operator console starts streaming after enrollment/preflight.
	installLog("install complete (service registered, not started)")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(windowsServiceName)
	_ = uninstallWindowsControlPlaneIntent()
	return nil
}

func installWindowsControlPlaneIntent() error {
	path := WindowsControlPlaneIntentPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("wfp=minimal\nminifilter=optional\n"), 0o644)
}

func uninstallWindowsControlPlaneIntent() error {
	path := WindowsControlPlaneIntentPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
