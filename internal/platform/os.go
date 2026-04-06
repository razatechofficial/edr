// Package platform provides OS detection, privilege management, and
// platform-specific path constants for the EDR agent.
package platform

import "runtime"

// OSType identifies the operating system.
type OSType string

const (
	// Linux identifies the Linux operating system.
	Linux OSType = "linux"
	// Darwin identifies macOS.
	Darwin OSType = "darwin"
	// Windows identifies the Windows operating system.
	Windows OSType = "windows"
)

// Current returns the current operating system type.
func Current() OSType { return OSType(runtime.GOOS) }

// IsLinux reports whether the current OS is Linux.
func IsLinux() bool { return runtime.GOOS == "linux" }

// IsDarwin reports whether the current OS is macOS.
func IsDarwin() bool { return runtime.GOOS == "darwin" }

// IsWindows reports whether the current OS is Windows.
func IsWindows() bool { return runtime.GOOS == "windows" }

// Arch returns the current CPU architecture.
func Arch() string { return runtime.GOARCH }
