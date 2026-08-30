//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func extraPurgeTreesFor(p installPaths) []string {
	return []string{
		"/Applications/EDR Agent.app",
		"/usr/local/libexec/edr-agent.app",
		filepath.Join(p.dataDir, "bin"),
		filepath.Join(p.dataDir, "installer"),
	}
}

func stopProductProcesses() {
	_ = exec.Command("killall", "-TERM", "edr-agent").Run()
	time.Sleep(300 * time.Millisecond)
	_ = exec.Command("killall", "-KILL", "edr-agent").Run()
}

func quitInstalledConsole() {
	// Path-scoped so EDR-Agent-Setup.app is not killed.
	_ = exec.Command("pkill", "-f", "/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui").Run()
	_ = exec.Command("pkill", "-f", "/usr/local/bin/edr-agent-ui").Run()
}

func forgetPackageReceipts() {
	for _, id := range []string{"com.razatech.edr-agent", "com.razatech.edr.consumer"} {
		if err := exec.Command("/usr/sbin/pkgutil", "--forget", id).Run(); err != nil {
			continue
		}
		fmt.Printf("    forgot package receipt %s\n", id)
	}
}

func purgeUserConsoleState() {
	user, home := darwinConsoleUser()
	if home == "" {
		return
	}
	_ = user
	for _, rel := range []string{
		"Library/Application Support/com.razatech.edr.console",
		"Library/Preferences/com.razatech.edr.console.plist",
		"Library/Caches/com.razatech.edr.console",
	} {
		p := filepath.Join(home, rel)
		if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    warning: %s: %v\n", p, err)
		}
	}
}

func darwinConsoleUser() (user, home string) {
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return "", ""
	}
	user = strings.TrimSpace(string(out))
	if user == "" || user == "root" || user == "loginwindow" {
		return "", ""
	}
	homeOut, err := exec.Command("dscl", ".", "-read", "/Users/"+user, "NFSHomeDirectory").Output()
	if err != nil {
		return user, ""
	}
	line := strings.TrimSpace(string(homeOut))
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return user, ""
	}
	return user, fields[len(fields)-1]
}
