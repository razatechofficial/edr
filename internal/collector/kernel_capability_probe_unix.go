//go:build unix

package collector

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func kernelCapabilityProbe() kernelCapability {
	k := kernelCapability{
		GOOS:             runtime.GOOS,
		CGOSupported:     cgoEnabledForProbe(),
		RunningAsRoot:    os.Geteuid() == 0,
		BPFSupported:     false,
		RuntimeGoVersion: runtime.Version(),
	}
	if p, err := exec.LookPath("dtrace"); err == nil && p != "" {
		k.DtracePresent = true
		k.DtracePath = p
	}
	k.ReasonSummary = summarizeKernelCapability(k)
	return k
}

func summarizeKernelCapability(k kernelCapability) string {
	var b strings.Builder
	b.WriteString("kernel tier not available on this GOOS build (capability probe); ")
	b.WriteString("goos=")
	b.WriteString(k.GOOS)
	b.WriteString("; cgo=")
	if k.CGOSupported {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("; euid_root=")
	if k.RunningAsRoot {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("; dtrace=")
	if k.DtracePresent {
		b.WriteString("present")
	} else {
		b.WriteString("absent")
	}
	b.WriteString("; bpf_supported=false")
	return b.String()
}
