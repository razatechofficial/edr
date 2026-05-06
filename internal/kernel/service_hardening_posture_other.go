//go:build !windows

package kernel

// WindowsServiceHardeningPosture is only populated on Windows agents.
func WindowsServiceHardeningPosture() map[string]any {
	return nil
}
