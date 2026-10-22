//go:build linux

package kernel

// The Linux half of SEC()-driven attach: one pass over the loaded collection
// that makes the attach call each program's section asks for.
//
// This replaces attachTracepoints and attachLSMPrograms, which keyed off Go
// symbol prefixes and between them reached 39 of the 62 programs in the
// object. The planning half lives in ebpf_attach.go with no build tag so the
// consistency tests can call it; everything here needs a kernel.
//
// Two behaviours are worth knowing before reading the code:
//
//   - Failure is per program. A kprobe whose symbol is absent from this
//     kernel, an LSM hook the kernel refuses, a tracepoint that does not exist
//     on this architecture: each is logged, recorded in attachMisses, and
//     surfaced on the capability report's category row, and the driver carries
//     on with what did attach. Only ebpfRequiredPrograms can fail the loader.
//   - Attach order is sorted by program name, so logs and the recorded miss
//     set are reproducible across runs. Go map iteration order is random and
//     made the old loader's WARN output impossible to diff between boots.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// attachPrograms attaches every program in the loaded collection according to
// its SEC() string, recording per-program outcomes.
//
// It returns an error only when a program in ebpfRequiredPrograms could not be
// attached, or when nothing attached at all. Everything else is a reported
// miss: the capability report is the surface for a partial attach, and killing
// the driver over one hook would take the other sixty with it.
func (d *EBPFDriver) attachPrograms() error {
	if d == nil || d.coll == nil {
		return fmt.Errorf("attaching ebpf programs: collection not loaded")
	}

	names := make([]string, 0, len(d.coll.Programs))
	for name := range d.coll.Programs {
		names = append(names, name)
	}
	sort.Strings(names)

	misses := make(map[string]string, len(names))
	for _, name := range names {
		prog := d.coll.Programs[name]
		if prog == nil {
			misses[name] = "program is nil in the loaded collection"
			continue
		}

		section := d.sectionForProgram(name)
		if section == "" {
			// Without a section there is nothing to attach from.
			// This is a loader bug rather than an environment
			// problem, so it is reported rather than guessed at.
			misses[name] = "no SEC() recorded for this program in the loaded CollectionSpec, so the loader cannot tell how to attach it"
			continue
		}

		target, attempt, skip := ebpfAttachDecision(name, section)
		if !attempt {
			misses[name] = skip
			continue
		}
		if why := d.featureGateFor(target); why != "" {
			misses[name] = why
			continue
		}
		if why := d.policyGateFor(name); why != "" {
			misses[name] = why
			continue
		}

		l, err := d.attachOne(name, prog, target)
		if err != nil {
			if why, required := ebpfRequiredPrograms[name]; required && !isOptionalTracepointAttachFailure(target.Group, target.Name, err) {
				return fmt.Errorf("attaching required program %s (%s): %w — %s", name, target, err, why)
			}
			reason := fmt.Sprintf("%s attach failed on this kernel: %v", target, err)
			misses[name] = reason
			fmt.Fprintf(os.Stderr, "WARN ebpf: %s not attached: %s\n", name, reason)
			continue
		}
		d.recordAttachment(name, target, prog, l)
	}

	if len(d.links) == 0 {
		return fmt.Errorf("no ebpf programs attached out of %d in the object; verify tracefs is mounted and the agent has CAP_BPF and CAP_PERFMON", len(names))
	}

	d.setAttachMisses(misses)
	fmt.Fprintf(os.Stderr, "INFO ebpf: attached %d of %d programs (%d not attached)\n", len(d.links), len(names), len(misses))
	return nil
}

// sectionForProgram returns the SEC() string recorded for a program at load
// time, or "" when none was recorded.
func (d *EBPFDriver) sectionForProgram(name string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.secByProg[name]
}

// recordSections captures every program's SEC() string from the collection
// spec before the spec is discarded.
//
// ebpf.Collection keeps no section names — only ebpf.CollectionSpec does — so
// this has to happen while bootstrapLoadedCollection still holds the spec.
// Reading the section from the object rather than from a table in Go is the
// whole point: the object is the thing that got loaded.
func (d *EBPFDriver) recordSections(spec *ebpf.CollectionSpec) {
	if d == nil || spec == nil {
		return
	}
	sections := make(map[string]string, len(spec.Programs))
	for name, ps := range spec.Programs {
		if ps == nil {
			continue
		}
		sections[name] = ps.SectionName
	}
	d.mu.Lock()
	d.secByProg = sections
	d.mu.Unlock()
}

// featureGateFor returns a reason when a probed kernel feature rules out this
// attach before it is attempted, or "" to go ahead.
//
// Pre-screening on a probed feature rather than letting the attach fail keeps
// the capability report's reason specific — "kernel does not have BPF LSM
// enabled" is actionable, and the errno the kernel returns for an LSM attach
// on a kernel without CONFIG_BPF_LSM is not.
// policyGateFor reports why the current policy does not want a program
// attached at all, as opposed to wanting its events discarded in userspace.
//
// The distinction was not being made, and for the scheduler programs it was
// expensive. EventPolicy.SchedEvents defaults to false "because of their
// volume", but it only suppressed forwarding: the three sched tracepoints
// stayed attached, ran on every context switch and submitted an event each
// time, which measured about 250,000 records a second on a hosted two-core
// runner. processRecord read and classified every one of them and returned
// without forwarding — and the CPU that cost starved the other ring buffer
// readers enough that file, module and mount events went missing from a test
// that generated them deliberately.
//
// A category gated off here reports unattached with this reason, which is a
// more useful thing for an operator to read than a silent category would be.
func (d *EBPFDriver) policyGateFor(name string) string {
	if d == nil {
		return ""
	}
	d.mu.RLock()
	sched := d.policy.SchedEvents
	d.mu.RUnlock()

	switch name {
	case "edr_tp_sched_switch", "edr_tp_sched_wakeup", "edr_tp_sched_migrate_task":
		if !sched {
			return "monitoring.sched_events is false, so the scheduler tracepoints are not attached: they fire on every context switch and submitting an event each time costs around a quarter of a million records a second, which starves the other subsystems"
		}
	}
	return ""
}

func (d *EBPFDriver) featureGateFor(t ebpfAttachTarget) string {
	switch t.Kind {
	case ebpfAttachLSM:
		if !d.features.HasBPFLSM {
			return "kernel does not list bpf in /sys/kernel/security/lsm, so BPF LSM programs cannot attach; add bpf to lsm= on the kernel command line"
		}
	case ebpfAttachTracepoint:
		if t.Group == "cgroup" && !d.features.HasCgroupBPF {
			return "no cgroup hierarchy is mounted at /sys/fs/cgroup, so the cgroup tracepoint group is not available"
		}
	}
	return ""
}

// attachOne makes the single attach call the target asks for, reusing a pinned
// link when one is already on bpffs.
//
// The pinned-link path is only tried for perf-based links (tracepoint, kprobe,
// kretprobe). LSM links are not pinned and reloaded here, matching what
// attachLSMPrograms did before.
func (d *EBPFDriver) attachOne(name string, prog *ebpf.Program, t ebpfAttachTarget) (link.Link, error) {
	if t.Kind != ebpfAttachLSM {
		if l := d.loadPinnedLinkFor(name); l != nil {
			return l, nil
		}
	}
	switch t.Kind {
	case ebpfAttachTracepoint:
		return link.Tracepoint(t.Group, t.Name, prog, nil)
	case ebpfAttachKprobe:
		return link.Kprobe(t.Symbol, prog, nil)
	case ebpfAttachKretprobe:
		return link.Kretprobe(t.Symbol, prog, nil)
	case ebpfAttachLSM:
		return link.AttachLSM(link.LSMOptions{Program: prog})
	}
	return nil, fmt.Errorf("no attach call for kind %q", t.Kind)
}

// loadPinnedLinkFor returns an already-pinned link for this program, or nil.
func (d *EBPFDriver) loadPinnedLinkFor(name string) link.Link {
	d.mu.RLock()
	base := strings.TrimSpace(d.bpfPinPath)
	d.mu.RUnlock()
	if base == "" {
		return nil
	}
	l, err := linkLoadPinnedFn(ebpfPinnedTraceLinkPath(base, name))
	if err != nil || l == nil {
		return nil
	}
	return l
}

// recordAttachment files a successful attach so the watchdog can re-create the
// link and the capability report can see it.
//
// The key is the kernel's program ID, which is also what watchdogLoop polls
// for disappearance. A program whose Info() call fails keeps its link — it is
// attached and producing — but cannot be re-attached by the watchdog, which is
// the pre-existing behaviour and is better than dropping the link.
func (d *EBPFDriver) recordAttachment(name string, t ebpfAttachTarget, prog *ebpf.Program, l link.Link) {
	d.links = append(d.links, l)
	info, err := prog.Info()
	if err != nil {
		return
	}
	id, ok := info.ID()
	if !ok {
		return
	}
	pid := uint32(id)
	d.linkByProg[pid] = l
	d.specByProg[pid] = tracepointAttachSpec{
		progName: name,
		group:    t.Group,
		tp:       t.Name,
		lsm:      t.Kind == ebpfAttachLSM,
		kind:     t.Kind,
		symbol:   t.Symbol,
	}
	d.tryPinTraceLink(name, l)
}

// setAttachMisses replaces the recorded set of programs that did not attach.
func (d *EBPFDriver) setAttachMisses(misses map[string]string) {
	d.mu.Lock()
	d.attachMisses = misses
	d.mu.Unlock()
}

// attachMissReasons returns a copy of the per-program reasons the last attach
// pass recorded.
//
// The capability report prefers these over any static table: a reason derived
// from the kernel that actually refused the attach beats a reason written by
// whoever last edited the source.
func (d *EBPFDriver) attachMissReasons() map[string]string {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.attachMisses) == 0 {
		return nil
	}
	out := make(map[string]string, len(d.attachMisses))
	for k, v := range d.attachMisses {
		out[k] = v
	}
	return out
}

// reattachBySpec re-creates the link for one previously attached program,
// using the attach kind recorded at first attach.
//
// The watchdog calls this when a program's ID has vanished from the kernel,
// which is the tamper signal. It has to honour the recorded kind: before
// kprobes could attach at all, every non-LSM re-attach was a tracepoint, and
// re-creating a kprobe link as link.Tracepoint("", "tcp_close") would fail
// every time and look like persistent tampering.
func (d *EBPFDriver) reattachBySpec(spec tracepointAttachSpec, prog *ebpf.Program) (link.Link, error) {
	kind := spec.kind
	if kind == "" {
		// Records written before the kind field existed, and any
		// future caller that only knows lsm vs not.
		kind = ebpfAttachTracepoint
		if spec.lsm {
			kind = ebpfAttachLSM
		}
	}
	t := ebpfAttachTarget{Kind: kind, Group: spec.group, Name: spec.tp, Symbol: spec.symbol}
	return d.attachOne(spec.progName, prog, t)
}
