//go:build !windows

package collector

// WireWindowsKernelRegistryETW is a no-op outside Windows.
func WireWindowsKernelRegistryETW(cols []Collector) {}
