//go:build linux || darwin || windows

package collector

func probeRareDNSSource(_ []string) (string, []string, string) { return "", nil, "unsupported" }
