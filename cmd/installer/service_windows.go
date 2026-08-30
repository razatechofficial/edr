//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsServiceName = "EDRAgent"

func installWindowsService(agentBin, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := openOrCreateWindowsService(m, agentBin, configPath)
	if err != nil {
		return err
	}
	defer s.Close()

	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)

	ensureAgentFirewall(agentBin)

	if flagNoStart {
		fmt.Println("    Windows Service installed (not started; --no-start)")
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("    Windows Service installed and started")
	return nil
}

func openOrCreateWindowsService(m *mgr.Mgr, agentBin, configPath string) (*mgr.Service, error) {
	if existing, err := m.OpenService(windowsServiceName); err == nil {
		_, _ = existing.Control(svc.Stop)
		cfg, cerr := existing.Config()
		if cerr == nil {
			cfg.StartType = mgr.StartAutomatic
			cfg.DelayedAutoStart = true
			cfg.DisplayName = "EDR Agent"
			cfg.Description = "Endpoint Detection and Response agent by RazaTech"
			cfg.BinaryPathName = `"` + agentBin + `" run --config "` + configPath + `"`
			_ = existing.UpdateConfig(cfg)
		}
		return existing, nil
	}

	var last error
	for i := 0; i < 3; i++ {
		if existing, err := m.OpenService(windowsServiceName); err == nil {
			_, _ = existing.Control(svc.Stop)
			_ = existing.Delete()
			_ = existing.Close()
			time.Sleep(200 * time.Millisecond)
		}
		s, err := m.CreateService(windowsServiceName, agentBin, mgr.Config{
			StartType:        mgr.StartAutomatic,
			DisplayName:      "EDR Agent",
			Description:      "Endpoint Detection and Response agent by RazaTech",
			DelayedAutoStart: true,
		}, "--config", configPath)
		if err == nil {
			return s, nil
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	if existing, err := m.OpenService(windowsServiceName); err == nil {
		return existing, nil
	}
	return nil, fmt.Errorf("create service: %w", last)
}

func stopWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return nil
}

func removeWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

func ensureAgentFirewall(agentBin string) {
	hidden := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		hideConsole(cmd)
		cmd.Stdout = nil
		cmd.Stderr = nil
		_ = cmd.Run()
	}
	hidden("netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR Agent")
	hidden("netsh", "advfirewall", "firewall", "add", "rule",
		"name=EDR Agent", "dir=out", "action=allow", "program="+agentBin, "enable=yes", "profile=any")
	hidden("netsh", "advfirewall", "firewall", "add", "rule",
		"name=EDR Agent", "dir=in", "action=allow", "program="+agentBin, "enable=yes", "profile=any")
}
