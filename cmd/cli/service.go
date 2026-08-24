package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the EDR agent service (requires administrator/root)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requirePrivileged(); err != nil {
				return err
			}
			return controlAgentService("start")
		},
	}
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the EDR agent service (requires administrator/root)",
		Long:  "Stopping the sensor requires administrator or root credentials (same pattern as CrowdStrike/SentinelOne/Defender).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requirePrivileged(); err != nil {
				return err
			}
			return controlAgentService("stop")
		},
	}
}

func controlAgentService(action string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("sc.exe", action, "EDRAgent")
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s service: %w (%s)", action, err, strings.TrimSpace(string(out)))
		}
		fmt.Printf("EDRAgent %s requested\n", action)
		return nil
	case "linux":
		out, err := exec.Command("systemctl", action, "edr-agent").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %s edr-agent: %w (%s)", action, err, strings.TrimSpace(string(out)))
		}
		fmt.Printf("edr-agent %s requested\n", action)
		return nil
	case "darwin":
		const label = "system/com.razatech.edr-agent"
		var cmd *exec.Cmd
		if action == "start" {
			cmd = exec.Command("launchctl", "kickstart", "-k", label)
		} else {
			cmd = exec.Command("launchctl", "bootout", label)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("launchctl %s: %w (%s)", action, err, strings.TrimSpace(string(out)))
		}
		fmt.Printf("com.razatech.edr-agent %s requested\n", action)
		return nil
	default:
		return fmt.Errorf("service control is not supported on %s", runtime.GOOS)
	}
}

func serviceRuntimeStatus() string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("sc.exe", "query", "EDRAgent")
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "unknown"
		}
		s := string(out)
		switch {
		case strings.Contains(s, "RUNNING"):
			return "running"
		case strings.Contains(s, "STOPPED"):
			return "stopped"
		case strings.Contains(s, "START_PENDING"):
			return "starting"
		default:
			return "installed"
		}
	case "linux":
		out, err := exec.Command("systemctl", "is-active", "edr-agent").CombinedOutput()
		if err != nil {
			return strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out))
	case "darwin":
		if err := exec.Command("launchctl", "print", "system/com.razatech.edr-agent").Run(); err != nil {
			return "not loaded"
		}
		return "loaded"
	default:
		return "unknown"
	}
}
