//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func windowsControlAgentService(action string) error {
	rights := uint32(windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG)
	switch action {
	case "start":
		rights |= windows.SERVICE_START
	case "stop":
		rights |= windows.SERVICE_STOP
	}
	s, closer, err := openEDRAgent(rights)
	if err != nil {
		return fmt.Errorf("%s EDRAgent: %w", action, err)
	}
	defer closer()
	switch action {
	case "start":
		if err := s.Start(); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "already running") || strings.Contains(msg, "already started") {
				fmt.Println("EDRAgent already running")
				return nil
			}
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
