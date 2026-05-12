//go:build !windows

package collector

func authWindowsSecurityTelemetry(*AuthCollector) ([]Telemetry, error) {
	return nil, nil
}

// authWindowsStop is a no-op on non-Windows platforms. The file-tail
// auth reader holds no long-lived OS resources to release.
func authWindowsStop(*AuthCollector) {}
