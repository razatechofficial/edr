//go:build !windows

package collector

// ComputeImpHash is only supported on Windows PE files.
func ComputeImpHash(string) (string, error) { return "", nil }

func ImphashPEFile(string) string { return "" }
