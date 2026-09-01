//go:build darwin

package hostperm

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const darwinSensorApp = "/usr/local/libexec/edr-agent.app"

const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

func revealSensorForFDA() {
	registerSensorApp()
	copyPasteboard(SensorFDAItemPath())
}

func registerSensorApp() {
	if st, err := os.Stat(darwinSensorApp); err != nil || !st.IsDir() {
		return
	}
	if _, err := os.Stat(lsregister); err != nil {
		return
	}
	_ = exec.Command(lsregister, "-f", darwinSensorApp).Run()
}

func SensorFDAItemPath() string {
	if st, err := os.Stat(darwinSensorApp); err == nil && st.IsDir() {
		return darwinSensorApp
	}
	return sensorBinaryHint()
}

func copyPasteboard(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	cmd := exec.Command("/usr/bin/pbcopy")
	cmd.Stdin = strings.NewReader(s)
	_ = cmd.Run()
}

func sensorProbeCandidates() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(filepath.Join(darwinSensorApp, "Contents", "MacOS", "edr-agent"))
	add(launchdSensorProgram())
	add(sensorBinaryHint())
	add("/Library/Application Support/EDR/bin/edr-agent")
	add("/usr/local/bin/edr-agent")
	return out
}

func confirmFDAViaApp() bool {
	return probeFDAViaLaunchServices()
}

func probeFDAViaLaunchServices() bool {
	if st, err := os.Stat(darwinSensorApp); err != nil || !st.IsDir() {
		return false
	}
	clearFDAProbeResult()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/open", "-W", "-n", "-g", "-j", darwinSensorApp, "--args", "fda-probe")
	_ = cmd.Run()
	if readFDAProbeResult() {
		return true
	}
	time.Sleep(400 * time.Millisecond)
	return readFDAProbeResult()
}

func probeFDADetached(bin string) bool {
	raw, err := os.ReadFile(bin)
	if err != nil || !bytes.Contains(raw, []byte("fda-probe")) {
		return false
	}
	cmd := exec.Command(bin, "fda-probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Run() == nil
}
