package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func agentUIBinaryName() string {
	if runtime.GOOS == "windows" {
		return "edr-agent-ui.exe"
	}
	return "edr-agent-ui"
}

func findAgentUIBinary(paths *installPaths) string {
	suffix := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		suffix += ".exe"
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			dir := filepath.Dir(exe)
			candidates = append(candidates,
				filepath.Join(dir, agentUIBinaryName()),
				filepath.Join(dir, "edr-agent-ui"+suffix),
				filepath.Join(dir, "bin", agentUIBinaryName()),
			)
		}
	}
	candidates = append(candidates,
		filepath.Join(".", agentUIBinaryName()),
		filepath.Join("bin", "edr-agent-ui"+suffix),
	)
	if paths != nil {
		staged := filepath.Join(paths.dataDir, "installer", "bin", agentUIBinaryName())
		candidates = append([]string{staged}, candidates...)
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func deployAgentUI(src string, paths installPaths) error {
	switch runtime.GOOS {
	case "windows":
		dst := filepath.Join(paths.binDir, agentUIBinaryName())
		if err := copyFile(src, dst, 0755); err != nil {
			return err
		}
		fmt.Printf("    %s -> %s\n", src, dst)
		return nil
	case "darwin":
		dst := filepath.Join(paths.binDir, agentUIBinaryName())
		if err := copyFile(src, dst, 0755); err != nil {
			return err
		}
		fmt.Printf("    %s -> %s\n", src, dst)
		app := "/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui"
		if err := os.MkdirAll(filepath.Dir(app), 0755); err == nil {
			if err := copyFile(src, app, 0755); err != nil {
				fmt.Printf("    warning: could not update EDR Agent.app: %v\n", err)
			} else {
				fmt.Printf("    %s -> %s\n", src, app)
			}
		}
		return nil
	default:
		dst := filepath.Join(paths.binDir, agentUIBinaryName())
		if err := copyFile(src, dst, 0755); err != nil {
			return err
		}
		fmt.Printf("    %s -> %s\n", src, dst)
		return nil
	}
}

func siblingAgentUI() string {
	return findAgentUIBinary(nil)
}

func runAttendedEntry(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unknown command %q (try install, uninstall, wizard, version)", strings.Join(args, " "))
	}
	if runtime.GOOS == "linux" {
		return runLinuxWizard()
	}
	return launchSiblingSetup()
}
