//go:build linux

package kernel

// Linux capability report tests.
//
// Three of these bind the report's tables to independently derived facts, so
// the tables cannot rot:
//
//   - the category table is checked against the programs actually present in
//     platform/linux/ebpf/*.c, so a new program cannot be added without a
//     category;
//   - the unattachable-hook reasons are checked against the set the eBPF
//     consistency tests derive from the loader source, so the operator-facing
//     reason strings cannot outlive the bug they describe;
//   - the event-type mapping is checked against the bpfEvt* constants parsed
//     out of driver_linux.go, so a new event type cannot be decoded into no
//     category.
//
// The fourth drives a real EBPFDriver value to prove attach state is read from
// the driver's own attach records and not from any static list.

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestLinuxCapabilityTableCoversEveryProgram asserts ebpfHookCategories and
// the C sources agree about which programs exist.
func TestLinuxCapabilityTableCoversEveryProgram(t *testing.T) {
	src, err := ParseEBPFSources(EBPFSourceDir())
	if err != nil {
		t.Fatalf("parsing ebpf sources: %v", err)
	}

	inSources := make(map[string]bool, len(src.Programs))
	for _, p := range src.Programs {
		inSources[p.Name] = true
		cats, ok := ebpfHookCategories[p.Name]
		if !ok {
			t.Errorf("eBPF program %s (%s:%d) has no entry in ebpfHookCategories.\n"+
				"Without one the capability report cannot say anything about the category it serves, so the hook is invisible to the console. Add it.",
				p.Name, p.File, p.Line)
			continue
		}
		if len(cats) == 0 {
			t.Errorf("eBPF program %s maps to an empty category list", p.Name)
		}
		for _, c := range cats {
			if !isCanonicalCapability(c) {
				t.Errorf("eBPF program %s maps to %q, which is not in CanonicalCapabilityCategories", p.Name, c)
			}
		}
	}

	for hook := range ebpfHookCategories {
		if !inSources[hook] {
			t.Errorf("ebpfHookCategories lists %q but no .c file in %s declares a program with that name; remove the stale entry", hook, EBPFSourceDir())
		}
	}
}

// TestLinuxUnattachableHooksMatchConsistencyAllowlist keeps the two records of
// the same debt in step.
//
// ebpfUnattachableHooks exists in shipped code so the capability report can
// tell an operator *why* a category is dark. knownUnattachedPrograms exists in
// the consistency test as the debt register. They describe the same three
// deliberately-unattached enforcement hooks and must stay identical: if one is
// updated when a program's attach path changes and the other is not, the agent
// reports a stale reason to operators, or the test silently stops guarding a
// program.
func TestLinuxUnattachableHooksMatchConsistencyAllowlist(t *testing.T) {
	for hook := range ebpfUnattachableHooks {
		if _, ok := knownUnattachedPrograms[hook]; !ok {
			t.Errorf("ebpfUnattachableHooks lists %q but knownUnattachedPrograms does not.\n"+
				"Either the program now attaches — remove it from ebpfUnattachableHooks so the report stops claiming it is dark — or add it to the consistency allowlist.", hook)
		}
	}
	for hook := range knownUnattachedPrograms {
		if _, ok := ebpfUnattachableHooks[hook]; !ok {
			t.Errorf("knownUnattachedPrograms lists %q but ebpfUnattachableHooks does not.\n"+
				"The capability report will show that category as unattached with a generic message instead of the real cause. Add it.", hook)
		}
	}
}

// TestLinuxEventTypeCategoryCoverage asserts every eBPF event type the Go side
// knows about maps to a capability category.
//
// The constant list is parsed out of driver_linux.go rather than restated, so
// adding a bpfEvt* constant without a category fails here instead of producing
// events that are decoded and forwarded but credited to nothing, which would
// make the category read "attached, not producing" forever.
func TestLinuxEventTypeCategoryCoverage(t *testing.T) {
	raw, err := os.ReadFile("driver_linux.go")
	if err != nil {
		t.Fatalf("reading driver_linux.go: %v", err)
	}

	re := regexp.MustCompile(`(?m)^\s*(bpfEvt[A-Za-z0-9_]*)\s*=\s*(\d+)\s*$`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatal("parsed no bpfEvt* constants from driver_linux.go; the constant block has moved and this test is no longer checking anything")
	}
	t.Logf("checking %d bpfEvt* constants", len(matches))

	for _, m := range matches {
		name, valStr := m[1], m[2]
		val, err := strconv.ParseUint(valStr, 10, 32)
		if err != nil {
			t.Errorf("constant %s has unparseable value %q: %v", name, valStr, err)
			continue
		}
		if cat := linuxCapabilityForEventType(uint32(val)); cat == "" {
			t.Errorf("event type %s (%d) maps to no capability category.\n"+
				"processRecord will decode and forward the event, but the capability report will never credit it, so its category reads attached-but-silent forever. Add it to linuxCapabilityForEventType.",
				name, val)
		} else if !isCanonicalCapability(cat) {
			t.Errorf("event type %s (%d) maps to %q, which is not in CanonicalCapabilityCategories", name, val, cat)
		}
	}
}

// TestLinuxCapabilityReportReadsAttachStateFromDriver proves the report is
// built from what the driver recorded at attach time, not from a static list.
//
// The driver value is constructed directly rather than through NewEBPFDriver,
// which requires root. specByProg is exactly what attachTracepoints and
// attachLSMPrograms populate on a successful link, so seeding it is a faithful
// stand-in for a partial attach — the state this whole report exists to
// surface.
func TestLinuxCapabilityReportReadsAttachStateFromDriver(t *testing.T) {
	const dnsMissReason = "tracepoint syscalls/sys_enter_sendto attach failed on this kernel: no such file or directory"

	d := &EBPFDriver{
		caps: newCapabilityTracker(),
		specByProg: map[uint32]tracepointAttachSpec{
			1: {progName: "tracepoint__syscalls__sys_enter_execve", group: "syscalls", tp: "sys_enter_execve", kind: ebpfAttachTracepoint},
			2: {progName: "fim_path_unlink", lsm: true, kind: ebpfAttachLSM},
		},
		// attachPrograms records one of these per program it could not
		// attach. Seeding it is a faithful stand-in for a kernel that
		// refused one hook.
		attachMisses: map[string]string{"tp_dns_sendto": dnsMissReason},
	}
	d.running.Store(true)
	d.caps.observe(CapProcessExec)

	rep := d.CapabilityReport()
	if rep.Driver != "ebpf" {
		t.Errorf("driver = %q, want ebpf", rep.Driver)
	}
	if !rep.DriverRunning {
		t.Error("driver_running should be true")
	}

	exec := findCapability(t, rep, CapProcessExec)
	if !exec.Present || !exec.Attached || !exec.Producing {
		t.Errorf("process_exec should be present+attached+producing from the seeded attach record and observation, got %+v", exec)
	}
	if len(exec.Attachments) != 1 || exec.Attachments[0] != "tracepoint__syscalls__sys_enter_execve" {
		t.Errorf("process_exec attachments = %v, want only the one program actually attached (lsm_bprm_check also serves this category but is not attached)", exec.Attachments)
	}

	del := findCapability(t, rep, CapFileDelete)
	if !del.Attached {
		t.Errorf("file_delete should be attached via the seeded fim_path_unlink record, got %+v", del)
	}
	if del.Producing {
		t.Error("file_delete should not be producing: nothing was observed for it")
	}

	// A category present in the build but with nothing in the attach
	// records must report a cause, and when the driver recorded a runtime
	// miss that cause has to be the kernel's, not a compile-time string.
	// This is what lets an operator tell "this kernel has no such symbol"
	// apart from "this loader never tries".
	dns := findCapability(t, rep, CapNetworkDNS)
	if !dns.Present {
		t.Error("network_dns should be present: tp_dns_sendto exists in the sources")
	}
	if dns.Attached {
		t.Error("network_dns must not be attached: tp_dns_sendto is not in the attach records")
	}
	if dns.Reason != dnsMissReason {
		t.Errorf("network_dns reason = %q, want the runtime attach-miss reason the driver recorded (%q) so an operator learns why DNS is dark on this host", dns.Reason, dnsMissReason)
	}

	// An LSM enforcement hook is left out by decision, not by failure, so
	// its category keeps the static reason from ebpfUnattachableHooks.
	// CapSignal is served by lsm_task_kill (attachable, not in the seeded
	// records) and nothing else, so it falls through to the generic
	// message; CapFileOpen is served by lsm_file_open among others.
	fileOpen := findCapability(t, rep, CapFileOpen)
	if fileOpen.Attached {
		t.Error("file_open must not be attached: no file_open hook is in the seeded attach records")
	}
	if fileOpen.Reason != ebpfReasonLSMEnforcement {
		t.Errorf("file_open reason = %q, want the LSM-enforcement decision from ebpfUnattachableHooks", fileOpen.Reason)
	}

	sched := findCapability(t, rep, CapScheduler)
	if sched.Attached {
		t.Error("scheduler must not be attached: no edr_tp_sched_* program is in the seeded attach records")
	}
}

// TestLinuxCapabilityReportStoppedDriver asserts a driver that never started
// reports every present category as stopped rather than as attached.
func TestLinuxCapabilityReportStoppedDriver(t *testing.T) {
	d := &EBPFDriver{
		caps:       newCapabilityTracker(),
		specByProg: make(map[uint32]tracepointAttachSpec),
	}
	rep := d.CapabilityReport()
	for _, c := range rep.Categories {
		if c.Attached {
			t.Errorf("category %q attached on a driver that never started", c.Category)
		}
		if c.Present && c.Derivation != DerivationDriverStopped {
			t.Errorf("category %q derivation = %q, want %q", c.Category, c.Derivation, DerivationDriverStopped)
		}
	}
}
