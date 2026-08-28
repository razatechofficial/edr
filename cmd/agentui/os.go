package main

import "runtime"

func isDarwin() bool  { return runtime.GOOS == "darwin" }
func isWindows() bool { return runtime.GOOS == "windows" }
func isLinux() bool   { return runtime.GOOS == "linux" }

// hostKind is the web lab AgentOs id: macos | windows | linux.
func hostKind() string {
	switch {
	case isDarwin():
		return "macos"
	case isWindows():
		return "windows"
	default:
		return "linux"
	}
}
