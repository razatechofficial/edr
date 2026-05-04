//go:build unix && !windows

package collector

import "testing"

func TestKernelCapabilityProbeFields(t *testing.T) {
	k := kernelCapabilityProbe()
	if k.GOOS == "" {
		t.Fatal("empty GOOS")
	}
	if k.RuntimeGoVersion == "" {
		t.Fatal("empty go version")
	}
	if k.ReasonSummary == "" {
		t.Fatal("empty reason summary")
	}
}
