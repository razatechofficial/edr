//go:build !windows

package collector

func authWindowsSecurityTelemetry(*AuthCollector) ([]Telemetry, error) {
	return nil, nil
}
