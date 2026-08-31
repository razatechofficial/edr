//go:build darwin

package hostperm

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const darwinSensorApp = "/usr/local/libexec/edr-agent.app"

func revealSensorForFDA() {
	item := SensorFDAItemPath()
	if item == "" {
		return
	}
	app := darwinSensorApp
	if st, err := os.Stat(app); err == nil && st.IsDir() {
		// Separate Launch Services launch so TCC lists EDR Sensor, not Setup.app.
		_ = exec.Command("/usr/bin/open", "-n", "-g", "-j", app, "--args", "fda-probe").Start()
		time.Sleep(250 * time.Millisecond)
	} else if bin := sensorBinaryHint(); bin != "" {
		cmd := exec.Command(bin, "fda-probe")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		_ = cmd.Start()
	}
	_ = exec.Command("/usr/bin/open", "-R", item).Start()
	copyPasteboard(item)
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

func probeFDADetached(bin string) bool {
	raw, err := os.ReadFile(bin)
	if err != nil || !bytes.Contains(raw, []byte("fda-probe")) {
		return false
	}
	cmd := exec.Command(bin, "fda-probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Run() == nil
}
