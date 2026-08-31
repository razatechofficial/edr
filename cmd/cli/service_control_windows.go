//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func windowsControlAgentService(action string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService("EDRAgent")
	if err != nil {
		return fmt.Errorf("%s service: EDRAgent is not registered (%w)", action, err)
	}
	defer s.Close()
	switch action {
	case "start":
		if err := s.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		fmt.Println("EDRAgent start requested")
		return nil
	case "stop":
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		fmt.Println("EDRAgent stop requested")
		return nil
	default:
		return fmt.Errorf("unsupported service action %q", action)
	}
}
