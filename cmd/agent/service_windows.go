//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsServiceName = "EDRAgent"
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
	return eventlog.InstallAsEventCreate(windowsServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
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
	return nil
}
