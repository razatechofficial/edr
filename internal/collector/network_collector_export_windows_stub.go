//go:build !windows

package collector

func (nc *NetworkCollector) exportNetworkHealthWindows() map[string]any {
	return nil
}
