//go:build windows

package main

import (
	"fmt"
	"time"

	"github.com/razatechofficial/edr/internal/hostperm"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func windowsControlAgentService(action string) error {
	if action == "start" {
		if err := hostperm.StartSensorService(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		fmt.Println("EDRAgent start requested")
		return nil
	}
	if action != "stop" {
		return fmt.Errorf("unsupported service action %q", action)
	}
	s, closer, err := openEDRAgent(windows.SERVICE_QUERY_STATUS | windows.SERVICE_STOP)
	if err != nil {
		return fmt.Errorf("stop EDRAgent: %w", err)
	}
	defer closer()
	if _, err := s.Control(svc.Stop); err != nil {
		if st, qerr := s.Query(); qerr == nil && st.State == svc.Stopped {
			fmt.Println("EDRAgent already stopped")
			return nil
		}
		return fmt.Errorf("stop service: %w", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err == nil && st.State == svc.Stopped {
			fmt.Println("EDRAgent stop requested")
			return nil
		}
		time.Sleep(400 * time.Millisecond)
	}
	fmt.Println("EDRAgent stop requested")
	return nil
}

func openEDRAgent(access uint32) (*mgr.Service, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, fmt.Errorf("service manager: %w", err)
	}
	name, err := windows.UTF16PtrFromString("EDRAgent")
	if err != nil {
		_ = windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	sh, err := windows.OpenService(scm, name, access)
	if err != nil {
		_ = windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	return &mgr.Service{Name: "EDRAgent", Handle: sh}, func() {
		_ = windows.CloseServiceHandle(sh)
		_ = windows.CloseServiceHandle(scm)
	}, nil
}
