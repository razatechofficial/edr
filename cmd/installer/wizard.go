package main

import (
	"fmt"
	"os"
	"os/exec"
)

const installerEULA = `EDR Agent is installed for all users of this computer (per-machine). It cannot be installed for a single account: host monitoring must cover every session on the device.

Telemetry is sent only to your organization’s XDR tenant. Stopping or removing the agent requires administrator credentials.

By choosing Accept you agree to the license terms. In enterprise fleets this screen is skipped: the organization accepts the license by deploying the package silently.`

func launchSiblingSetup() error {
	ui := siblingAgentUI()
	if ui == "" {
		fmt.Fprintln(os.Stderr, "Attended setup needs edr-agent-ui next to this installer.")
		fmt.Fprintln(os.Stderr, "Silent fleet:  "+os.Args[0]+" install")
		fmt.Fprintln(os.Stderr, "Or copy edr-agent-ui into this folder and run this program again.")
		return fmt.Errorf("EDR Agent UI not found")
	}
	cmd := exec.Command(ui, "--setup")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runLinuxWizard() error {
	if err := requirePrivileged(); err != nil {
		return err
	}
	fmt.Println("EDR Agent — license agreement")
	fmt.Println()
	fmt.Println(installerEULA)
	fmt.Println()
	fmt.Println("Installs for all users of this computer. Required for host monitoring.")
	fmt.Print("Accept license? [y/N]: ")
	var ans string
	_, _ = fmt.Scanln(&ans)
	if ans != "y" && ans != "Y" && ans != "yes" {
		fmt.Println("Setup was cancelled. EDR Agent was not installed.")
		return nil
	}
	flagNoStart = true
	if err := runInstall(nil, nil); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Files are installed. This host is not enrolled yet.")
	fmt.Println("Next: edr-agent-ui")
	fmt.Println("Or:   sudo edrctl enroll --token \"$TOKEN\"")
	fmt.Println("Then: sudo systemctl start edr-agent")
	return nil
}

