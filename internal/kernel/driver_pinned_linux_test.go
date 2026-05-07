//go:build linux

package kernel

import "testing"

func TestEbpfPinnedTraceLinkPath(t *testing.T) {
	t.Parallel()
	p := ebpfPinnedTraceLinkPath("/sys/fs/bpf/edr", "tracepoint__sched__sched_switch")
	if p != "/sys/fs/bpf/edr/link_tracepoint__sched__sched_switch" {
		t.Fatal(p)
	}
}
