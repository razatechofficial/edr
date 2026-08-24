//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

func installService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(windowsServiceName); err == nil {
		_, _ = existing.Control(svc.Stop)
		_ = existing.Delete()
		_ = existing.Close()
		time.Sleep(2 * time.Second)
	}

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

	s, err := m.CreateService(
		windowsServiceName,
		exePath,
		mgr.Config{
			StartType:    mgr.StartAutomatic,
			DisplayName:  "EDR Agent",
			Description:  "Endpoint Detection and Response Agent",
			DelayedAutoStart: false,
		},
		"--config", cfgPath,
	)
	if err != nil {
		return err
	}
	defer s.Close()

	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
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
		return err
	}

	var posture map[string]any
	if c, err := config.Load(cfgPath); err == nil {
		posture = applyWindowsServiceHardening(s, exePath, c)
	} else {
		posture = map[string]any{"applied": false, "reason": "config_unavailable", "error": err.Error()}
	}
	_ = writeServiceHardeningPosture(posture)
	if err := installWindowsControlPlaneIntent(); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
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
