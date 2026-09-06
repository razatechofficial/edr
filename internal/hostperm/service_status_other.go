//go:build !windows

package hostperm

// SensorRuntimeStatus is Windows-only; other platforms use edrctl status.
func SensorRuntimeStatus() string { return "" }
