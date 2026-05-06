//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/config"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsServiceName = "EDRAgent"
	windowsControlPlaneIntentPath = `C:\ProgramData\EDR Agent\control_plane.intent`
)

func installService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(windowsServiceName); err == nil {
		_ = existing.Close()
		return fmt.Errorf("%s service already exists", windowsServiceName)
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	s, err := m.CreateService(
		windowsServiceName,
		exePath,
		mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: "EDR Agent",
			Description: "Endpoint Detection and Response Agent",
		},
		"--config", `C:\ProgramData\EDR Agent\config.yml`,
	)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = eventlog.Remove(windowsServiceName)
	if err := eventlog.InstallAsEventCreate(windowsServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return err
	}
	cfgPath := `C:\ProgramData\EDR Agent\config.yml`
	var posture map[string]any
	if c, err := config.Load(cfgPath); err == nil {
		posture = applyWindowsServiceHardening(s, exePath, c)
	} else {
		posture = map[string]any{"applied": false, "reason": "config_unavailable", "error": err.Error()}
	}
	_ = writeServiceHardeningPosture(posture)
	return installWindowsControlPlaneIntent()
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
	if err := os.MkdirAll(filepath.Dir(windowsControlPlaneIntentPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(windowsControlPlaneIntentPath, []byte("wfp=minimal\nminifilter=optional\n"), 0o644)
}

func uninstallWindowsControlPlaneIntent() error {
	if err := os.Remove(windowsControlPlaneIntentPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
