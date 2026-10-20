//go:build linux

package kernel

// Linux capability report: which event categories the eBPF driver is actually
// serving right now.
//
// Attach state comes from d.specByProg, which attachPrograms populates with
// one entry per successful link call. That is real runtime evidence and not a
// static list: a program that failed to attach because the tracepoint does not
// exist on this kernel, or because a kprobe's symbol is absent from
// /proc/kallsyms, or because a hardened kernel denied the perf link, is absent
// from that map and so reported unattached here.
//
// The *reason* a category is dark comes from d.attachMisses, which the same
// pass fills with the kernel's own error for each program it could not attach.
// That is preferred over the static tables below, because an errno from the
// kernel that refused the attach is worth more to an operator than a string
// written by whoever last edited this file.
//
// Producing state comes from the per-category counters the event loop updates
// in processRecord, which is the single point every ring buffer record passes
// through.

import (
	"sort"
)

// ebpfHookCategories maps each eBPF program name to the event categories it
// serves.
//
// Written hook-first because that is how it is maintained — add a program to
// the C sources, add a line here — and because
// TestLinuxCapabilityTableCoversEveryProgram can then check it against the
// programs actually present in platform/linux/ebpf/*.c and fail when a new
// program arrives without a category.
//
// A program appears here whether or not the loader can attach it. That is the
// point: the report's job is to distinguish "no mechanism exists" from "a
// mechanism exists and is not attached", and collapsing the second into the
// first would hide exactly the failure this file was written to expose.
var ebpfHookCategories = map[string][]CapabilityCategory{
	// process_monitor.c
	"tracepoint__syscalls__sys_enter_execve":   {CapProcessExec},
	"tracepoint__syscalls__sys_enter_execveat": {CapProcessExec},
	"tracepoint__sched__sched_process_fork":    {CapProcessFork},
	"tracepoint__sched__sched_process_exit":    {CapProcessExit},

	// file_monitor.c
	"tracepoint__syscalls__sys_enter_openat":    {CapFileOpen},
	"tracepoint__syscalls__sys_exit_openat":     {CapFileOpen},
	"tracepoint__syscalls__sys_enter_close":     {CapFileOpen},
	"tracepoint__syscalls__sys_enter_write":     {CapFileWrite},
	"tracepoint__syscalls__sys_enter_pwrite64":  {CapFileWrite},
	"tracepoint__syscalls__sys_enter_unlinkat":  {CapFileDelete},
	"tracepoint__syscalls__sys_enter_rename":    {CapFileRename},
	"tracepoint__syscalls__sys_enter_renameat":  {CapFileRename},
	"tracepoint__syscalls__sys_enter_renameat2": {CapFileRename},
	"tracepoint__syscalls__sys_enter_fchmodat":  {CapFilePermission},
	"kprobe_mem_write":                          {CapMemoryWrite},

	// lsm_fim.c — observe-only FIM, the only LSM programs the loader attaches.
	"fim_path_unlink":   {CapFileDelete},
	"fim_path_rename":   {CapFileRename},
	"fim_inode_setattr": {CapFilePermission},

	// network_monitor.c
	"tracepoint__syscalls__sys_enter_connect": {CapNetworkConnect},
	"tracepoint__syscalls__sys_enter_accept":  {CapNetworkAccept},
	"tracepoint__syscalls__sys_enter_accept4": {CapNetworkAccept},
	"tracepoint__syscalls__sys_enter_bind":    {CapNetworkBind},
	"tp_dns_sendto":                           {CapNetworkDNS},
	"kp_tcp_v4_connect":                       {CapNetworkConnect},
	"kp_tcp_v6_connect":                       {CapNetworkConnect},
	"kp_udp_sendmsg":                          {CapNetworkConnect, CapNetworkDNS},
	"kp_udp_recvmsg":                          {CapNetworkConnect},
	"kretp_udp_recvmsg":                       {CapNetworkConnect},
	"kp_tcp_close":                            {CapNetworkClose},
	"kp_inet_sock_set_state":                  {CapNetworkClose},

	// syscall_monitor.c
	"tracepoint__syscalls__sys_enter_ptrace":        {CapPtrace},
	"tracepoint__syscalls__sys_enter_init_module":   {CapModuleLoad},
	"tracepoint__syscalls__sys_enter_finit_module":  {CapModuleLoad},
	"tracepoint__syscalls__sys_enter_delete_module": {CapModuleUnload},
	"tracepoint__syscalls__sys_enter_setuid":        {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_setgid":        {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_setreuid":      {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_setregid":      {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_setresuid":     {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_setresgid":     {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_capset":        {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_prctl":         {CapCredentialChange},
	"tracepoint__syscalls__sys_enter_mount":         {CapMount},
	"tracepoint__syscalls__sys_enter_clone":         {CapProcessFork},
	"tracepoint__syscalls__sys_enter_clone3":        {CapProcessFork},
	"tracepoint__syscalls__sys_enter_sendto":        {CapNetworkConnect},
	"tracepoint__syscalls__sys_enter_unshare":       {CapNamespaceChange},
	"tracepoint__syscalls__sys_enter_madvise":       {CapMemoryWrite},
	"lsm_bpf_prog":     {CapModuleLoad},
	"lsm_bpf_map_prog": {CapModuleLoad},
	"tp_cgroup_attach": {CapNamespaceChange},
	"tp_cgroup_mkdir":  {CapNamespaceChange},
	"tp_seccomp":       {CapNamespaceChange},

	// lsm_hooks.c — enforcement-capable hooks, none attached today.
	"lsm_bprm_check":            {CapProcessExec},
	"lsm_file_open":             {CapFileOpen},
	"lsm_socket_connect":        {CapNetworkConnect},
	"lsm_task_kill":             {CapSignal},
	"lsm_kernel_module_request": {CapModuleLoad},

	// sched_monitor.c
	"edr_tp_sched_switch":       {CapScheduler},
	"edr_tp_sched_wakeup":       {CapScheduler},
	"edr_tp_sched_migrate_task": {CapScheduler},

	// tls_sni_monitor.c
	"kp_tls_tcp_sendmsg": {CapTLSMetadata},
}

// Reasons a program in ebpfHookCategories is not attached in this build.
//
// There used to be three causes and twenty-three affected programs, all of
// them loader defects: no link.Kprobe call existed, LSM attach keyed off the
// fim_ symbol prefix, and tracepoint attach keyed off the
// tracepoint__<group>__<name> symbol prefix. attachPrograms now plans from
// each program's SEC() string, so all three causes are gone and the only
// programs left out are left out on purpose.
//
// ebpfUnattachableHooks below assigns a reason to each, and
// TestLinuxUnattachableHooksMatchConsistencyAllowlist asserts its key set is
// exactly the set the eBPF consistency tests independently derive from the
// sources, so the two cannot drift apart.
const ebpfReasonLSMEnforcement = "LSM enforcement hook: the program returns -EPERM on a deny-list hit, so attaching it would let the agent block exec, open or connect host-wide with no policy surface to control it, and it only emits on a deny-list hit so with the deny-list maps unwritten it would produce nothing either"

// ebpfAttachedHookCaveats records defects in programs that DO attach, so the
// capability report does not present a category as healthy when the events it
// produces are unusable. buildCapabilityReport carries these through on
// attached categories as well as unattached ones.
var ebpfAttachedHookCaveats = map[string]string{
	"tracepoint__syscalls__sys_enter_accept":  ebpfReasonAcceptNoAddresses,
	"tracepoint__syscalls__sys_enter_accept4": ebpfReasonAcceptNoAddresses,
}

// TODO(monitoring): parse the accepted peer address in the accept/accept4
// programs, or move inbound-connection telemetry to the attached
// inet_sock_set_state path once kprobe attach exists.
const ebpfReasonAcceptNoAddresses = "attached and producing, but the accept/accept4 programs in network_monitor.c submit the event immediately after memset and fill_header without parsing a sockaddr, so every inbound-connection event carries zeroed local and remote addresses and ports"

// ebpfUnattachableHooks records why each program the loader deliberately does
// not attach is left out, so the capability report can tell an operator the
// cause instead of only that a category is dark.
//
// A program that attachPrograms *tries* to attach and fails is not listed
// here: its reason comes from d.attachMisses at runtime, carrying the kernel's
// own error.
var ebpfUnattachableHooks = map[string]string{
	"lsm_bprm_check":     ebpfReasonLSMEnforcement,
	"lsm_file_open":      ebpfReasonLSMEnforcement,
	"lsm_socket_connect": ebpfReasonLSMEnforcement,
}

// linuxCapabilityForEventType maps a raw eBPF event type to the category the
// tracker should credit.
//
// Kept exhaustive over the bpfEvt* constants so that a new event type added to
// common.h and decoded in processRecord without a category here shows up as a
// silent gap in the report rather than being credited to the wrong row.
// TestLinuxEventTypeCategoryCoverage asserts every bpfEvt* constant is mapped.
func linuxCapabilityForEventType(typ uint32) CapabilityCategory {
	switch typ {
	case bpfEvtProcExec:
		return CapProcessExec
	case bpfEvtProcExit:
		return CapProcessExit
	case bpfEvtProcFork:
		return CapProcessFork
	case bpfEvtFileOpen:
		return CapFileOpen
	case bpfEvtFileWrite:
		return CapFileWrite
	case bpfEvtFileDel, bpfEvtLSMFimUnlink:
		return CapFileDelete
	case bpfEvtFileRen, bpfEvtLSMFimRename:
		return CapFileRename
	case bpfEvtFileChmod, bpfEvtLSMFimSetattr:
		return CapFilePermission
	case bpfEvtNetConn:
		return CapNetworkConnect
	case bpfEvtNetAccept:
		return CapNetworkAccept
	case bpfEvtNetBind:
		return CapNetworkBind
	case bpfEvtNetClose:
		return CapNetworkClose
	case bpfEvtDNSQuery:
		return CapNetworkDNS
	case bpfEvtModule, bpfEvtBPFLoad, bpfEvtBPFMapAccess:
		return CapModuleLoad
	case bpfEvtMount:
		return CapMount
	case bpfEvtPtrace:
		return CapPtrace
	case bpfEvtSignal:
		return CapSignal
	case bpfEvtPrivilege:
		return CapCredentialChange
	case bpfEvtUnshare, bpfEvtCgroupAttach, bpfEvtCgroupMkdir, bpfEvtSeccomp:
		return CapNamespaceChange
	case bpfEvtMadvise, bpfEvtProcMemWrite:
		return CapMemoryWrite
	case bpfEvtSchedSwitch, bpfEvtSchedWakeup, bpfEvtSchedMigrate:
		return CapScheduler
	}
	return ""
}

// attachedHookNames returns the set of program names the driver recorded a
// successful attach for.
func (d *EBPFDriver) attachedHookNames() map[string]bool {
	out := make(map[string]bool)
	if d == nil {
		return out
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, spec := range d.specByProg {
		if spec.progName != "" {
			out[spec.progName] = true
		}
	}
	return out
}

// CapabilityReport reports what the eBPF driver has actually attached and what
// it has actually seen. It implements CapabilityReporter.
func (d *EBPFDriver) CapabilityReport() CapabilityReport {
	if d == nil {
		return emptyCapabilityReport("ebpf", "no eBPF driver instance")
	}

	running := d.running.Load()
	// Unattachable hooks and caveats on attached hooks share one reason
	// table: both are things an operator needs to see on the category row.
	reasons := make(map[string]string, len(ebpfUnattachableHooks)+len(ebpfAttachedHookCaveats))
	for k, v := range ebpfUnattachableHooks {
		reasons[k] = v
	}
	for k, v := range ebpfAttachedHookCaveats {
		reasons[k] = v
	}
	// Runtime beats static. A program the kernel refused carries the
	// kernel's error here, which tells an operator whether the fix is a
	// kernel config, a missing capability or a symbol that does not exist
	// on this kernel -- none of which a compile-time table can know.
	for k, v := range d.attachMissReasons() {
		reasons[k] = v
	}
	mechanisms := capabilityMechanismsFor("ebpf", ebpfHookCategories, reasons)

	// A loaded collection with no attached programs is a different failure
	// from a driver that never started, and the reason should say which.
	attached := d.attachedHookNames()
	notBuilt := "no eBPF program in platform/linux/ebpf serves this category"
	if running && len(attached) == 0 {
		notBuilt = "eBPF driver is running but recorded no attachments; the object may have loaded without any link succeeding"
	}

	return buildCapabilityReport(
		"ebpf",
		running,
		d.Stats().UptimeSeconds,
		mechanisms,
		attached,
		DerivationRuntimeAttach,
		d.caps,
		notBuilt,
	)
}

// AttachedProgramNames returns the sorted names of attached eBPF programs.
// Exported for the integration tests, which need to skip with an accurate
// message when the hook a test depends on is not attached on this kernel.
func (d *EBPFDriver) AttachedProgramNames() []string {
	set := d.attachedHookNames()
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	// Sorted output keeps skip messages and test logs diffable.
	sort.Strings(out)
	return out
}
