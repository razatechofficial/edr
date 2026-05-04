//go:build windows

package collector

import (
	"runtime"
	"strings"
)

func kernelCapabilityProbeWindows() kernelCapability {
	k := kernelCapability{
		GOOS:             runtime.GOOS,
		CGOSupported:     cgoEnabledForProbe(),
		RunningAsRoot:    isWindowsElevated(),
		BPFSupported:     false,
		RuntimeGoVersion: runtime.Version(),
	}
	var b strings.Builder
	b.WriteString("kernel tier capability (windows); cgo=")
	if k.CGOSupported {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("; elevated=")
	if k.RunningAsRoot {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	k.ReasonSummary = b.String()
	return k
}
