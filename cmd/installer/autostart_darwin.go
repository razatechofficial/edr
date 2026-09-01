//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

const darwinUILaunchAgentPlist = "/Library/LaunchAgents/com.razatech.edr-agent-ui.plist"

const launchAgentUIPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.razatech.edr-agent-ui</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.UIBin}}</string>
		<string>--tray</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>LimitLoadToSessionType</key>
	<array>
		<string>Aqua</string>
	</array>
</dict>
</plist>
`

func installLoginAutostart(paths installPaths) error {
	ui := "/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui"
	if st, err := os.Stat(ui); err != nil || st.IsDir() {
		alt := paths.binDir + "/edr-agent-ui"
		if st, err := os.Stat(alt); err == nil && !st.IsDir() {
			ui = alt
		} else {
			fmt.Println("    skip login item: EDR Agent.app not installed")
			return nil
		}
	}
	tmpl, err := template.New("ui-agent").Parse(launchAgentUIPlist)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(darwinUILaunchAgentPlist, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("login LaunchAgent: %w", err)
	}
	if err := tmpl.Execute(f, struct{ UIBin string }{UIBin: ui}); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Close()
	fmt.Printf("    login item %s (all users)\n", darwinUILaunchAgentPlist)

	if out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output(); err == nil {
		user := strings.TrimSpace(string(out))
		if user != "" && user != "root" && user != "loginwindow" {
			if uidOut, err := exec.Command("id", "-u", user).Output(); err == nil {
				uid := strings.TrimSpace(string(uidOut))
				if lc, err := darwinLaunchctlPath(); err == nil && uid != "" {
					target := "gui/" + uid
					_ = exec.Command(lc, "bootout", target+"/com.razatech.edr-agent-ui").Run()
					_ = exec.Command(lc, "bootstrap", target, darwinUILaunchAgentPlist).Run()
				}
			}
		}
	}
	return nil
}

func removeLoginAutostart() {
	if out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output(); err == nil {
		user := strings.TrimSpace(string(out))
		if user != "" && user != "root" && user != "loginwindow" {
			if uidOut, err := exec.Command("id", "-u", user).Output(); err == nil {
				uid := strings.TrimSpace(string(uidOut))
				if lc, err := darwinLaunchctlPath(); err == nil && uid != "" {
					_ = exec.Command(lc, "bootout", "gui/"+uid+"/com.razatech.edr-agent-ui").Run()
				}
			}
		}
	}
	_ = os.Remove(darwinUILaunchAgentPlist)
}
