//go:build linux || darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
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

// uninstallService removes the service definition and reports what failed.
//
// Every error here used to be discarded and the function returned nil, so a
// non-root `--uninstall` printed nothing and exited 0 with the agent still
// running, still enrolled and still reporting. That is the worst failure an
// uninstall can have: the operator believes the sensor is gone and stops
// looking at it.
//
// Removal continues past a failure rather than returning at the first one, so a
// partial uninstall gets as far as it can, and every problem is reported
// together instead of one per run.
func uninstallService() error {
	var problems []string
	note := func(what string, err error) {
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", what, err))
		}
	}
	// A missing unit or plist means the work is already done, which is success.
	removeFile := func(path string) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			note("remove "+path, err)
		}
	}

	switch runtime.GOOS {
	case "linux":
		// `stop` and `disable` are tolerated when the unit is already gone;
		// systemctl exits non-zero for a unit it cannot find, and that is not
		// an uninstall failure.
		if out, err := exec.Command("systemctl", "stop", "edr-agent").CombinedOutput(); err != nil && !unitAbsent(out) {
			note("systemctl stop", fmt.Errorf("%v: %s", err, bytes.TrimSpace(out)))
		}
		if out, err := exec.Command("systemctl", "disable", "edr-agent").CombinedOutput(); err != nil && !unitAbsent(out) {
			note("systemctl disable", fmt.Errorf("%v: %s", err, bytes.TrimSpace(out)))
		}
		removeFile("/etc/systemd/system/edr-agent.service")
		if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			note("systemctl daemon-reload", fmt.Errorf("%v: %s", err, bytes.TrimSpace(out)))
		}
	case "darwin":
		const plistPath = "/Library/LaunchDaemons/com.razatech.edr-agent.plist"
		// bootout is the modern form and unload the legacy one; only report a
		// failure when both were refused, since either alone is sufficient.
		outNew, errNew := exec.Command("launchctl", "bootout", "system", plistPath).CombinedOutput()
		if errNew != nil {
			outOld, errOld := exec.Command("launchctl", "unload", plistPath).CombinedOutput()
			if errOld != nil {
				note("launchctl bootout/unload", fmt.Errorf("bootout: %v: %s; unload: %v: %s",
					errNew, bytes.TrimSpace(outNew), errOld, bytes.TrimSpace(outOld)))
			}
		}
		removeFile(plistPath)
	default:
		return fmt.Errorf("unsupported unix platform %s", runtime.GOOS)
	}

	if len(problems) > 0 {
		return fmt.Errorf("uninstall incomplete, the agent may still be running: %s",
			strings.Join(problems, "; "))
	}
	return nil
}

// unitAbsent reports systemctl complaining about a unit that is not there,
// which for an uninstall is the desired state rather than an error.
func unitAbsent(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "not loaded") ||
		strings.Contains(s, "could not be found") ||
		strings.Contains(s, "no such file or directory")
}
