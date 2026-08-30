package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func installedConsolePathMarkers() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui",
			"/usr/local/bin/edr-agent-ui",
		}
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return []string{filepath.Join(pf, "EDR Agent", "edr-agent-ui.exe")}
	default:
		return []string{"/usr/local/bin/edr-agent-ui"}
	}
}

func installedConsoleRunning() bool {
	return len(installedConsolePIDs()) > 0
}

func installedConsolePIDs() []int {
	var pids []int
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq edr-agent-ui.exe", "/FO", "CSV", "/NH")
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(strings.ToLower(line), "edr-agent-ui.exe") {
				continue
			}
			fields := strings.Split(line, ",")
			if len(fields) < 2 {
				continue
			}
			n, err := strconv.Atoi(strings.Trim(fields[1], `"`))
			if err == nil && n > 0 {
				pids = append(pids, n)
			}
		}
	default:
		for _, marker := range installedConsolePathMarkers() {
			out, err := exec.Command("pgrep", "-f", marker).CombinedOutput()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				n, err := strconv.Atoi(strings.TrimSpace(line))
				if err == nil && n > 0 && n != os.Getpid() {
					pids = append(pids, n)
				}
			}
		}
	}
	return uniqueInts(pids)
}

func uniqueInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, n := range in {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func quitInstalledConsoleUI() error {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("osascript", "-e", `tell application "EDR Agent" to quit`).Run()
		time.Sleep(400 * time.Millisecond)
	}
	for _, marker := range installedConsolePathMarkers() {
		if runtime.GOOS == "windows" {
			cmd := exec.Command("taskkill", "/F", "/IM", "edr-agent-ui.exe")
			hideConsole(cmd)
			_ = cmd.Run()
			break
		}
		_ = exec.Command("pkill", "-f", marker).Run()
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if !installedConsoleRunning() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	if installedConsoleRunning() {
		return errConsoleStillOpen
	}
	return nil
}

var errConsoleStillOpen = errString("EDR Agent is still open. Quit it from the menu bar, then try again.")

type errString string

func (e errString) Error() string { return string(e) }
