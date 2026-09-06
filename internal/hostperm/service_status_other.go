//go:build !windows

package hostperm

// SensorRuntimeStatus is Windows-only; other platforms use edrctl status.
func SensorRuntimeStatus() string { return "" }

// SensorPID is Windows-only.
func SensorPID() uint32 { return 0 }
