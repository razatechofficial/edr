//go:build linux

package kernel

// Per-program run counts, from the kernel's own BPF statistics.
//
// event_stats answers what happened to an event once a handler decided to emit
// one. It cannot answer the question before that: did the handler run at all?
// A category can read "attached: true, producing: false, submitted: 0,
// reserve_failed: 0, filtered: 0" and that state has two very different
// causes — a link the kernel accepted but never invokes, and a hook that fires
// on a path the test never takes — which no counter inside the program can
// distinguish, because a program that does not run increments nothing.
//
// The kernel keeps a run count per program under BPF_STATS_RUN_TIME. It is
// off by default because it costs two timestamp reads per invocation, so this
// is opt-in: the integration suite turns it on so a failure can say "the
// execve tracepoint ran 0 times" instead of "no event arrived", and an
// operator diagnosing a dark category in the field can turn it on with
// EDR_BPF_PROG_RUN_STATS=1 without a rebuild.
//
// Enabling is system-wide and reference-counted by the kernel on the returned
// fd: statistics stay on while any process holds one. Closing it is therefore
// part of driver shutdown, not optional.

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
)

// ProgramRunStat is one program's kernel-side execution record.
type ProgramRunStat struct {
	Program string `json:"program"`

	// RunCount is how many times the kernel has invoked the program. Zero
	// on an attached program means the hook is not being reached, which is
	// a different fault from a hook that is reached and loses its records.
	RunCount uint64 `json:"run_count"`

	// RecursionMisses counts invocations the kernel skipped because the
	// program was already running on that CPU. Non-zero is a real event
	// loss with no record anywhere else.
	RecursionMisses uint64 `json:"recursion_misses,omitempty"`

	// Runtime is the program's cumulative execution time.
	RuntimeNanos uint64 `json:"runtime_nanos,omitempty"`
}

// ebpfProgRunStatsEnv turns the statistics on without a code change.
const ebpfProgRunStatsEnv = "EDR_BPF_PROG_RUN_STATS"

// enableProgramRunStatsIfRequested honours ebpfProgRunStatsEnv at Start.
//
// Failure is reported and never fatal: a kernel older than 5.8 has no
// BPF_ENABLE_STATS, and losing a diagnostic is not a reason to lose
// monitoring.
func (d *EBPFDriver) enableProgramRunStatsIfRequested() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ebpfProgRunStatsEnv))) {
	case "1", "true", "yes":
	default:
		return
	}
	if err := d.EnableProgramRunStats(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN ebpf: %s is set but per-program run statistics could not be enabled: %v\n",
			ebpfProgRunStatsEnv, err)
	}
}

// EnableProgramRunStats turns on the kernel's per-program run counters.
//
// Exported because the integration suite needs them unconditionally: the
// question "is this attached program being invoked" is the one its failures
// turn on, and a suite that could not ask it spent several runs unable to say
// whether a silent category was a dead link or a full buffer.
//
// Calling it twice is a no-op rather than a second system-wide enable.
func (d *EBPFDriver) EnableProgramRunStats() error {
	if d == nil {
		return fmt.Errorf("no eBPF driver instance")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.progRunStats != nil {
		return nil
	}
	closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		return fmt.Errorf("enabling BPF_STATS_RUN_TIME (needs Linux 5.8 and CAP_SYS_ADMIN): %w", err)
	}
	d.progRunStats = closer
	return nil
}

// disableProgramRunStats releases the system-wide enable.
func (d *EBPFDriver) disableProgramRunStats() {
	if d == nil {
		return
	}
	d.mu.Lock()
	closer := d.progRunStats
	d.progRunStats = nil
	d.mu.Unlock()
	if closer != nil {
		_ = closer.Close()
	}
}

// ProgramRunStatsEnabled reports whether this driver turned the counters on.
//
// A caller has to be able to tell "ran zero times" from "not counted", for
// the same reason KernelLossReport.Available exists: reporting an unmeasured
// zero as a measurement asserts the absence of a fault nobody looked for.
func (d *EBPFDriver) ProgramRunStatsEnabled() bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.progRunStats != nil
}

// ProgramRunCounts returns one record per program in the loaded collection,
// busiest first. Programs the kernel reports nothing for are omitted.
func (d *EBPFDriver) ProgramRunCounts() []ProgramRunStat {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	coll := d.coll
	d.mu.RUnlock()
	if coll == nil {
		return nil
	}

	out := make([]ProgramRunStat, 0, len(coll.Programs))
	for name, prog := range coll.Programs {
		if prog == nil {
			continue
		}
		st, err := prog.Stats()
		if err != nil || st == nil {
			continue
		}
		out = append(out, ProgramRunStat{
			Program:         name,
			RunCount:        st.RunCount,
			RecursionMisses: st.RecursionMisses,
			RuntimeNanos:    uint64(st.Runtime / time.Nanosecond),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RunCount != out[j].RunCount {
			return out[i].RunCount > out[j].RunCount
		}
		return out[i].Program < out[j].Program
	})
	return out
}

// ProgramRunTotalFor sums the run counts of the named programs.
//
// counted is false when the statistics were never enabled, so a caller can
// print "not measured" instead of a zero that looks like a measurement.
func (d *EBPFDriver) ProgramRunTotalFor(programs []string) (total uint64, counted bool) {
	if d == nil || len(programs) == 0 || !d.ProgramRunStatsEnabled() {
		return 0, false
	}
	want := make(map[string]bool, len(programs))
	for _, p := range programs {
		want[p] = true
	}
	for _, st := range d.ProgramRunCounts() {
		if want[st.Program] {
			total += st.RunCount
		}
	}
	return total, true
}

// ebpfRunCountControlRows is how many of the busiest programs
// ProgramRunCountsFor prints as a control.
const ebpfRunCountControlRows = 8

// ProgramRunCountsFor renders the run counts of the named programs, which is
// what a dark capability category needs: the report row already lists the
// hooks that serve it, and this says whether the kernel is calling them.
//
// It always prints the busiest programs underneath, as a control. "runs=0" on
// its own does not distinguish a hook the kernel never reached from statistics
// that were not actually being collected, and reading the first as the second
// would send the next person looking in the wrong place. If the control rows
// are also zero, nothing was measured and nothing here means anything.
func (d *EBPFDriver) ProgramRunCountsFor(programs []string) string {
	if d == nil || len(programs) == 0 {
		return ""
	}
	if !d.ProgramRunStatsEnabled() {
		return fmt.Sprintf("per-program run counts: not collected (set %s=1 or call EnableProgramRunStats before Start)", ebpfProgRunStatsEnv)
	}
	want := make(map[string]bool, len(programs))
	for _, p := range programs {
		want[p] = true
	}
	all := d.ProgramRunCounts()

	var b strings.Builder
	b.WriteString("per-program run counts:")
	found := false
	for _, st := range all {
		if !want[st.Program] {
			continue
		}
		found = true
		fmt.Fprintf(&b, "\n    %s: runs=%d recursion_misses=%d", st.Program, st.RunCount, st.RecursionMisses)
		if st.RunCount == 0 {
			b.WriteString("  <- the kernel has never invoked this program")
		}
	}
	if !found {
		b.WriteString(" none of the named programs is in the loaded collection")
	}

	fmt.Fprintf(&b, "\n  busiest programs, as a control on the counts above (%d CPUs):", runtime.NumCPU())
	if len(all) == 0 {
		b.WriteString(" none; the collection has no programs")
		return b.String()
	}
	n := ebpfRunCountControlRows
	if len(all) < n {
		n = len(all)
	}
	for _, st := range all[:n] {
		fmt.Fprintf(&b, "\n    %s: runs=%d", st.Program, st.RunCount)
	}
	if all[0].RunCount == 0 {
		b.WriteString("\n    every program reads zero, so the statistics are not being collected and no count above is evidence of anything")
	}
	return b.String()
}
