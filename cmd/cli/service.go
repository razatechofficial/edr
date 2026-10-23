package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/razatechofficial/edr/internal/localapi"
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
		out, err := exec.Command("sc.exe", action, "EDRAgent").CombinedOutput()
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

// serviceRuntimeStatus probes the platform service manager and returns a
// canonical state.
//
// The three managers answer in three vocabularies and callers used to compare
// the raw strings, so a loaded launchd job read as unhealthy on macOS while an
// active systemd unit and a running Windows service read as healthy. The
// per-OS mapping lives in localapi.NormalizeServiceState; this function only
// has to extract the manager's own word for the state.
func serviceRuntimeStatus() localapi.ServiceState {
	return localapi.NormalizeServiceState(runtime.GOOS, rawServiceState())
}

// rawServiceState returns the service manager's own description of the
// service, unnormalised.
func rawServiceState() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("sc.exe", "query", "EDRAgent").CombinedOutput()
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
			// is-active exits non-zero for every state that is not active and
			// still prints the state, so the output is the answer.
			return strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out))
	case "darwin":
		// launchctl print succeeds for any loaded job, running or not, and its
		// dump carries the real state on a "state = ..." line. Reading it is
		// the difference between "the job is installed" and "the sensor is up".
		out, err := exec.Command("launchctl", "print", "system/com.razatech.edr-agent").CombinedOutput()
		if err != nil {
			return "not loaded"
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "state = ") {
				continue
			}
			return strings.TrimSpace(strings.TrimPrefix(line, "state = "))
		}
		return "loaded"
	default:
		return "unknown"
	}
}
