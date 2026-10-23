package kernel

// Attach planning for eBPF programs, derived from the SEC() string.
//
// The loader used to decide what to attach from the Go symbol name: a program
// was a tracepoint if its C function was called tracepoint__<group>__<name>,
// and an LSM hook was attached only if its function started with fim_. Nothing
// else got an attach call at all, so the nine kprobe and kretprobe programs in
// the object loaded into the kernel and never fired, and seven tracepoints
// whose authors named the function something else were skipped even though
// their SEC() named a perfectly attachable tracepoint.
//
// The SEC() string is the authoritative statement of how a program attaches —
// it is what libbpf, bpftool and every other loader reads — and cilium/ebpf
// preserves it verbatim on ebpf.ProgramSpec.SectionName. Planning from the
// section instead of from the symbol means a C author cannot accidentally
// opt a program out of being attached by choosing a function name, which is
// what happened to DNS, scheduler and TLS telemetry.
//
// This file is deliberately free of build tags and of any cilium/ebpf import:
// it is pure string handling over the section name, so it compiles and is
// testable on darwin and windows, and the eBPF consistency tests can call the
// real planner over the parsed C sources rather than modelling it. A model
// that is the code it models cannot drift from it.

import (
	"fmt"
	"strings"
)

// ebpfAttachKind is the kernel attach API a program needs.
type ebpfAttachKind string

const (
	ebpfAttachTracepoint ebpfAttachKind = "tracepoint"
	ebpfAttachKprobe     ebpfAttachKind = "kprobe"
	ebpfAttachKretprobe  ebpfAttachKind = "kretprobe"
	ebpfAttachLSM        ebpfAttachKind = "lsm"
)

// ebpfAttachTarget is everything the loader needs to make one attach call,
// extracted from a SEC() string.
//
// Exactly one of the target fields is meaningful per Kind: Group+Name for a
// tracepoint, Symbol for a kprobe or kretprobe, Hook for an LSM program.
type ebpfAttachTarget struct {
	Kind   ebpfAttachKind
	Group  string // tracepoint group, e.g. "syscalls"
	Name   string // tracepoint name, e.g. "sys_enter_execve"
	Symbol string // kernel symbol for kprobe/kretprobe, e.g. "tcp_close"
	Hook   string // LSM hook name, e.g. "path_unlink"
}

// String renders the target the way an operator would search for it, so log
// lines and capability-report reasons name something greppable in
// /sys/kernel/debug/tracing or /proc/kallsyms.
func (t ebpfAttachTarget) String() string {
	switch t.Kind {
	case ebpfAttachTracepoint:
		return "tracepoint " + t.Group + "/" + t.Name
	case ebpfAttachKprobe:
		return "kprobe " + t.Symbol
	case ebpfAttachKretprobe:
		return "kretprobe " + t.Symbol
	case ebpfAttachLSM:
		return "lsm " + t.Hook
	}
	return "unknown target"
}

// parseEBPFSection turns a SEC() string into an attach target.
//
// Only the four section families this object actually uses are recognised. An
// unrecognised section is an error rather than a silent skip, because a silent
// skip is the failure mode this whole change exists to remove: adding a
// SEC("fentry/...") or SEC("uprobe/...") program should make the loader say it
// does not know how to attach it, not quietly load it and move on.
func parseEBPFSection(section string) (ebpfAttachTarget, error) {
	s := strings.TrimSpace(section)
	if s == "" {
		return ebpfAttachTarget{}, fmt.Errorf("empty SEC() string")
	}
	prefix, rest, ok := strings.Cut(s, "/")
	if !ok || rest == "" {
		return ebpfAttachTarget{}, fmt.Errorf("SEC(%q) has no target after the attach type", section)
	}

	switch prefix {
	case "tracepoint", "tp":
		group, name, ok := strings.Cut(rest, "/")
		if !ok || group == "" || name == "" {
			return ebpfAttachTarget{}, fmt.Errorf("SEC(%q) is not tracepoint/<group>/<name>", section)
		}
		return ebpfAttachTarget{Kind: ebpfAttachTracepoint, Group: group, Name: name}, nil
	case "kprobe":
		if strings.Contains(rest, "/") {
			return ebpfAttachTarget{}, fmt.Errorf("SEC(%q) is not kprobe/<symbol>", section)
		}
		return ebpfAttachTarget{Kind: ebpfAttachKprobe, Symbol: rest}, nil
	case "kretprobe":
		if strings.Contains(rest, "/") {
			return ebpfAttachTarget{}, fmt.Errorf("SEC(%q) is not kretprobe/<symbol>", section)
		}
		return ebpfAttachTarget{Kind: ebpfAttachKretprobe, Symbol: rest}, nil
	case "lsm":
		if strings.Contains(rest, "/") {
			return ebpfAttachTarget{}, fmt.Errorf("SEC(%q) is not lsm/<hook>", section)
		}
		return ebpfAttachTarget{Kind: ebpfAttachLSM, Hook: rest}, nil
	}
	return ebpfAttachTarget{}, fmt.Errorf("SEC(%q): no attach API is wired up for the %q section family", section, prefix)
}

// ebpfEnforcementLSMPrograms are the LSM programs that can return -EPERM, and
// are therefore not attached.
//
// This is a deliberate decision, not an oversight, and it is the one place in
// this change where a program that *could* now be attached still is not.
// Three things make attaching them wrong today:
//
//  1. They are not observers. lsm_bprm_check, lsm_file_open and
//     lsm_socket_connect each look the subject up in a deny-list map and
//     return -EPERM on a hit, which fails the exec, the open or the connect
//     for the whole machine. Attaching an enforcement hook is a policy
//     decision the agent has no API to make: there is no interface anywhere
//     that would let an operator turn it off once it is on.
//  2. They would produce nothing anyway. All three only submit to lsm_events
//     on a deny-list hit, and nothing in the agent ever writes
//     exec_deny_list, file_deny_list or connect_deny_list — grep the tree for
//     those three map names and the only hits are the C definitions. With the
//     maps empty every lookup misses, every program returns 0, and no event is
//     ever reserved. So attaching them buys zero telemetry.
//  3. The cost is not zero. lsm/file_open runs on every open(2) on the host
//     and does a bpf_probe_read_kernel_str plus a 256-byte-key hash lookup
//     before deciding to do nothing.
//
// lsm_task_kill and lsm_kernel_module_request in the same file are pure
// observers — they submit unconditionally and always return 0 — so they are
// attached, which is what revives the lsm_events ring buffer. The two LSM
// programs in syscall_monitor.c (lsm_bpf_prog, lsm_bpf_map_prog) are likewise
// observe-only and are attached.
//
// Reviving these three properly means building a deny-list policy surface:
// map writes from EventPolicy, a kill switch, and an audit trail of what was
// blocked. That is a feature, not a loader fix.
var ebpfEnforcementLSMPrograms = map[string]string{
	"lsm_bprm_check":     "returns -EPERM on an exec_deny_list hit, so attaching it lets the agent block process execution host-wide; nothing writes exec_deny_list, so it would also emit nothing",
	"lsm_file_open":      "returns -EPERM on a file_deny_list hit, so attaching it lets the agent block file opens host-wide; nothing writes file_deny_list, so it would also emit nothing, while running on every open(2)",
	"lsm_socket_connect": "returns -EPERM on a connect_deny_list hit, so attaching it lets the agent block outbound connections host-wide; nothing writes connect_deny_list, so it would also emit nothing",
}

// ebpfRequiredPrograms are the hooks whose absence means the agent is not
// doing the job it was installed for, keyed to why.
//
// Everything else degrades: a hook that cannot attach on this kernel is logged
// and reported through the capability report, and the driver carries on with
// the hooks that did take. That is a change from the old loader, which failed
// the whole eBPF driver when any tracepoint outside
// isOptionalTracepointAttachFailure's list failed to link — meaning one absent
// tracepoint cost the host every other hook as well. On arm64 that was not
// hypothetical: tracepoint__syscalls__sys_enter_rename cannot attach there
// because arm64 has no rename(2), only renameat/renameat2, so the old loader
// refused to start at all on arm64 hosts.
//
// These three are present on every kernel with CONFIG_TRACEPOINTS, on every
// architecture, so a failure here is a real environment problem (no
// tracefs, no perf_event_open, a seccomp profile on the agent itself) and
// starting half-blind would hide it.
var ebpfRequiredPrograms = map[string]string{
	"tracepoint__syscalls__sys_enter_execve": "process execution is the spine of every detection rule; without it the agent reports nothing worth having",
	"tracepoint__sched__sched_process_fork":  "process ancestry cannot be rebuilt without fork, so exec events lose their parent chain",
	"tracepoint__sched__sched_process_exit":  "without exit the process table grows without bound and every process is reported as still running",
}

// ebpfAttachDecision reports what the loader will do with one program.
//
// attempt is true when the loader will make an attach call for it. When it is
// false, skip states why in operator terms, and that string is what the
// capability report shows on the affected category. Both the loader and the
// consistency tests go through here, so "the loader attaches this" has exactly
// one definition.
//
// Note that a true attempt is not a promise of attachment: the symbol may be
// absent from this kernel, or the hook may be denied. Those are runtime facts
// the loader records separately, which is why the capability report
// distinguishes present from attached.
func ebpfAttachDecision(progName, section string) (target ebpfAttachTarget, attempt bool, skip string) {
	t, err := parseEBPFSection(section)
	if err != nil {
		return ebpfAttachTarget{}, false, err.Error()
	}
	if t.Kind == ebpfAttachLSM {
		if why, enforcement := ebpfEnforcementLSMPrograms[progName]; enforcement {
			return t, false, "LSM enforcement hook, not attached by design: " + why
		}
	}
	return t, true, ""
}
