//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func installService() error {
	switch runtime.GOOS {
	case "linux":
		unit := `[Unit]
Description=EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/edr-agent --config /etc/edr-agent/config.yml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`
		if err := os.WriteFile("/etc/systemd/system/edr-agent.service", []byte(unit), 0o644); err != nil {
			return err
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", "edr-agent").Run()
		return exec.Command("systemctl", "start", "edr-agent").Run()
	case "darwin":
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.razatech.edr-agent</string>
<key>ProgramArguments</key><array>
<string>/usr/local/bin/edr-agent</string><string>run</string><string>--config</string><string>/Library/Application Support/EDR/config/agent.yaml</string>
</array>
<key>RunAtLoad</key><false/>
<key>KeepAlive</key>
<dict>
<key>Crashed</key><true/>
</dict>
<key>StandardOutPath</key><string>/Library/Logs/EDR/stdout.log</string>
<key>StandardErrorPath</key><string>/Library/Logs/EDR/stderr.log</string>
</dict></plist>
`
		const plistPath = "/Library/LaunchDaemons/com.razatech.edr-agent.plist"
		if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootout", "system", plistPath).Run()
		_ = exec.Command("launchctl", "unload", plistPath).Run()
		if err := exec.Command("launchctl", "bootstrap", "system", plistPath).Run(); err != nil {
			return exec.Command("launchctl", "load", plistPath).Run()
		}
		return nil
	default:
		return fmt.Errorf("unsupported unix platform %s", runtime.GOOS)
	}
}

func uninstallService() error {
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("systemctl", "stop", "edr-agent").Run()
		_ = exec.Command("systemctl", "disable", "edr-agent").Run()
		_ = os.Remove("/etc/systemd/system/edr-agent.service")
		_ = exec.Command("systemctl", "daemon-reload").Run()
		return nil
	case "darwin":
		const plistPath = "/Library/LaunchDaemons/com.razatech.edr-agent.plist"
		_ = exec.Command("launchctl", "bootout", "system", plistPath).Run()
		_ = exec.Command("launchctl", "unload", plistPath).Run()
		_ = os.Remove(plistPath)
		return nil
	default:
		return fmt.Errorf("unsupported unix platform %s", runtime.GOOS)
	}
}
