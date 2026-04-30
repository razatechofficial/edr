//go:build windows

package collector

// WireWindowsKernelRegistryETW links the registry polling collector to the
// kernel ETW session so polling is suppressed while Kernel-Registry ETW is active.
func WireWindowsKernelRegistryETW(cols []Collector) {
	var kc *KernelCollector
	var rc *RegistryCollector
	for _, c := range cols {
		switch t := c.(type) {
		case *KernelCollector:
			kc = t
		case *RegistryCollector:
			rc = t
		}
	}
	if kc == nil || rc == nil {
		return
	}
	kc.registryPeer = rc
}
