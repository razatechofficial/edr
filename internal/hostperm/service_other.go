//go:build !windows

package hostperm

// EnsureSensorService is Windows-only; other OSes register via package scripts.
func EnsureSensorService(exePath, cfgPath string) error {
	return nil
}
