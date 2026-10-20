//go:build linux

package kernel

import (
	"fmt"
	"os"
)

// selfFilterMaps are the per-subsystem PID allow-to-drop maps the eBPF
// programs already consult before emitting anything.
//
// Each program calls its own pid_is_filtered() against one of these and returns
// early on a hit. The kernel side has always been there; nothing ever wrote to
// them, so pid_is_filtered() was permanently false and the agent observed
// itself.
var selfFilterMaps = []string{
	"pid_filter",      // process_monitor.c — exec, fork, exit
	"file_pid_filter", // file_monitor.c and lsm_fim.c — open, write, unlink, rename, chmod
	"net_pid_filter",  // network_monitor.c — connect, accept, bind
	"sec_pid_filter",  // syscall_monitor.c — ptrace, module, credential, namespace
}

// installSelfFilter tells the kernel to drop events produced by the agent
// itself.
//
// Without it the agent is its own loudest source. Every telemetry batch it
// ships is a write syscall, every forensic bundle upload is a large transfer to
// the platform, and both come back through the same hooks as events the agent
// then processes and ships — which produces more writes. Analysts see the
// agent's own uploads reported as "large data transfer to host", and an analyst
// who learns to ignore one class of alert has been trained to ignore alerts.
//
// Filtering in the kernel rather than in userspace is the point: a userspace
// drop still pays for the event's allocation, its JSON encode, and a trip
// through the ring buffer, and it does nothing about the feedback loop. These
// maps sit in front of all of that.
//
// Failure is reported but never fatal. Monitoring with self-noise beats no
// monitoring, and a kernel that does not expose one of these maps is a kernel
// where that subsystem is not running anyway.
func (d *EBPFDriver) installSelfFilter(extraPIDs []uint32) error {
	if d == nil || d.coll == nil {
		return fmt.Errorf("self filter: no ebpf collection loaded")
	}

	// The thread group id, which is what bpf_get_current_pid_tgid() >> 32
	// returns — not the OS thread id. Go moves goroutines between threads, so
	// a per-thread id would filter some of the agent's work and not the rest.
	pids := []uint32{uint32(os.Getpid())}
	pids = append(pids, extraPIDs...)

	var val uint8 = 1
	var failed []string
	d.mu.Lock()
	d.selfFiltered = append([]uint32(nil), pids...)
	d.mu.Unlock()
	installed := 0
	for _, name := range selfFilterMaps {
		m, ok := d.coll.Maps[name]
		if !ok {
			// Not an error: a build without that subsystem has no such map.
			continue
		}
		for _, pid := range pids {
			if err := m.Put(pid, val); err != nil {
				failed = append(failed, fmt.Sprintf("%s/%d: %v", name, pid, err))
				continue
			}
			installed++
		}
	}

	if installed == 0 {
		return fmt.Errorf("self filter: no pid filter map accepted an entry (%v)", failed)
	}
	if len(failed) > 0 {
		return fmt.Errorf("self filter: %d entries installed, some rejected: %v", installed, failed)
	}
	return nil
}

// SelfFilteredPIDs reports what the agent asked the kernel to drop, so the
// health surface can show it rather than leaving an operator to infer it from
// the absence of events.
func (d *EBPFDriver) SelfFilteredPIDs() []uint32 {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]uint32(nil), d.selfFiltered...)
}
