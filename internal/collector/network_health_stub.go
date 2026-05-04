//go:build linux || darwin || windows

package collector

// exportOtherPlatformNetworkHealth is only invoked on tier-minimal GOOS builds;
// this stub satisfies the linker on Linux/macOS/Windows where the branch is never taken.
func exportOtherPlatformNetworkHealth(nc *NetworkCollector) map[string]any {
	_ = nc
	return nil
}
