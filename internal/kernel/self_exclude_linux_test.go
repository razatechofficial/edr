//go:build linux

package kernel

import (
	"os"
	"testing"
)

// The agent must be excluded from its own hooks in the kernel, not in
// userspace.
//
// It is its own highest-volume source: every telemetry batch is a write
// syscall, every evidence upload is a large transfer to the platform, and both
// come back through the same hooks as events the agent then ships — which
// produces more writes. Filtering in userspace would still pay for the
// allocation, the JSON encode and the ring-buffer trip, and would not break the
// loop.
func TestSelfFilterMapsCoverEverySubsystemThatEmits(t *testing.T) {
	// One map per emitting subsystem. A subsystem missing from this list is a
	// subsystem that still reports the agent's own activity.
	want := map[string]string{
		"pid_filter":      "process: exec, fork, exit",
		"file_pid_filter": "file: open, write, unlink, rename, chmod",
		"net_pid_filter":  "network: connect, accept, bind",
		"sec_pid_filter":  "syscall: ptrace, module, credential, namespace",
	}
	if len(selfFilterMaps) != len(want) {
		t.Fatalf("%d filter maps listed, expected %d: %v", len(selfFilterMaps), len(want), selfFilterMaps)
	}
	for _, name := range selfFilterMaps {
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected filter map %q", name)
		}
		delete(want, name)
	}
	for name, subsystem := range want {
		t.Errorf("%s is not self-filtered (%s)", name, subsystem)
	}
}

func TestInstallSelfFilterRefusesWithoutACollection(t *testing.T) {
	// Reported rather than silently skipped: a driver with no collection has
	// nothing to filter, and pretending otherwise would claim protection that
	// is not there.
	d := &EBPFDriver{}
	if err := d.installSelfFilter(nil); err == nil {
		t.Fatal("a driver with no ebpf collection reported a working self filter")
	}
	var nilDriver *EBPFDriver
	if err := nilDriver.installSelfFilter(nil); err == nil {
		t.Fatal("a nil driver reported a working self filter")
	}
}

func TestSelfFilteredPIDsIsSafeBeforeInstall(t *testing.T) {
	var nilDriver *EBPFDriver
	if got := nilDriver.SelfFilteredPIDs(); got != nil {
		t.Fatalf("nil driver returned %v", got)
	}
	d := &EBPFDriver{}
	if got := d.SelfFilteredPIDs(); len(got) != 0 {
		t.Fatalf("fresh driver reported %v as filtered", got)
	}
}

func TestTheAgentFiltersItsOwnThreadGroup(t *testing.T) {
	// bpf_get_current_pid_tgid() >> 32 is the thread group id, not the thread
	// id. Go moves goroutines between OS threads, so filtering a thread id
	// would exclude some of the agent's work and leave the rest reporting.
	d := &EBPFDriver{}
	_ = d.installSelfFilter(nil) // fails: no collection, but records the pids
	got := d.SelfFilteredPIDs()
	if len(got) == 0 {
		t.Fatal("no pid was recorded for filtering")
	}
	if got[0] != uint32(os.Getpid()) {
		t.Fatalf("filtered pid %d, expected the process group id %d", got[0], os.Getpid())
	}
}

func TestPolicyMutePIDsAreFilteredToo(t *testing.T) {
	// MutePIDs existed but was honoured only on macOS, so a policy that muted
	// a noisy process had no effect on Linux at all.
	d := &EBPFDriver{}
	_ = d.installSelfFilter([]uint32{4242, 9001})
	got := d.SelfFilteredPIDs()
	found := map[uint32]bool{}
	for _, p := range got {
		found[p] = true
	}
	for _, want := range []uint32{uint32(os.Getpid()), 4242, 9001} {
		if !found[want] {
			t.Errorf("pid %d was not recorded for filtering; got %v", want, got)
		}
	}
}
