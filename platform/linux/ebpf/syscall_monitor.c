// SPDX-License-Identifier: GPL-2.0
// Security-sensitive syscall monitoring for EDR agent.
// Compiled with: clang -O2 -target bpf -D__TARGET_ARCH_x86 -c syscall_monitor.c -o syscall_monitor.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} sec_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} sec_pid_filter SEC(".maps");

static __always_inline void fill_header(struct edr_event_hdr *hdr, __u32 type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid  = bpf_get_current_uid_gid();

	hdr->type      = type;
	hdr->pid       = pid_tgid >> 32;
	hdr->uid       = uid_gid & 0xFFFFFFFF;
	hdr->gid       = uid_gid >> 32;
	hdr->timestamp = bpf_ktime_get_ns();
	hdr->ppid      = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

static __always_inline bool pid_is_filtered(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&sec_pid_filter, &pid))
		return false;
	edr_stat_filtered(EDR_SUBSYS_SECURITY);
	return true;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_PTRACE);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PTRACE);

	/* ptrace(2): args[0]=request, args[1]=pid, args[2]=addr */
	evt->arg0 = ctx->args[0];
	evt->arg1 = ctx->args[1];
	evt->arg2 = ctx->args[2];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int tracepoint__syscalls__sys_enter_init_module(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_MODULE_LOAD);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MODULE_LOAD);

	/* init_module(2): args[0]=module_image, args[1]=len, args[2]=param_values */
	evt->arg0 = ctx->args[0];
	evt->arg1 = ctx->args[1];

	const char *params = (const char *)ctx->args[2];
	if (params)
		bpf_probe_read_user_str(evt->path, sizeof(evt->path), params);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int tracepoint__syscalls__sys_enter_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_MODULE_LOAD);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MODULE_LOAD);

	/* finit_module(2): args[0]=fd, args[1]=param_values, args[2]=flags */
	evt->arg0 = ctx->args[0];
	evt->arg2 = ctx->args[2];

	const char *params = (const char *)ctx->args[1];
	if (params)
		bpf_probe_read_user_str(evt->path, sizeof(evt->path), params);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Privilege-change syscalls emit EVENT_PRIVILEGE (was EVENT_SIGNAL). The
 * helper macro keeps the body identical across all six entry points; each
 * concrete tracepoint records the canonical x86_64 __NR_* and forwards as
 * many of args[0..2] as that syscall actually has.
 *
 * How many it has is not cosmetic. A sys_enter_<syscall> tracepoint publishes
 * exactly one field per real argument, and the kernel refuses to attach a
 * program that reads past the last one:
 *
 *	if (is_tracepoint || is_syscall_tp) {
 *		int off = trace_event_get_offsets(event->tp_event);
 *		if (prog->aux->max_ctx_offset > off)
 *			return -EACCES;
 *	}			-- kernel/events/core.c
 *
 * This macro used to read args[0..2] unconditionally. setuid(2) and setgid(2)
 * take one argument and setreuid(2) and setregid(2) take two, so all four
 * exceeded their tracepoint's format and all four failed to attach on every
 * kernel, with the loader reporting the -EACCES as
 *
 *	tracepoint syscalls/sys_enter_setuid attach failed on this kernel:
 *	cannot create bpf perf link: permission denied
 *
 * which reads like a hardened kernel or a missing capability rather than a
 * program that asks for an argument the syscall does not have. The agent
 * therefore could not see setuid or setgid at all -- the two most direct
 * privilege changes on the system -- while setresuid and setresgid, which do
 * take three arguments, attached and made the category look served.
 *
 * PRIV_ARGS_n copies the first n arguments and nothing more. It has to be the
 * preprocessor rather than `if (nargs > 1)` on a constant: the verifier's
 * max_ctx_offset counts loads in the emitted program, so correctness would
 * then depend on the optimiser eliminating a dead branch.
 */
#define PRIV_ARGS_1 evt->arg0 = ctx->args[0]
#define PRIV_ARGS_2 PRIV_ARGS_1; evt->arg1 = ctx->args[1]
#define PRIV_ARGS_3 PRIV_ARGS_2; evt->arg2 = ctx->args[2]

#define EMIT_PRIVILEGE_EVENT(NR, COPY_ARGS)                                   \
	do {                                                                  \
		if (pid_is_filtered())                                        \
			return 0;                                             \
		struct security_event *evt = edr_ringbuf_reserve(             \
			&sec_events, sizeof(*evt), EVENT_PRIVILEGE);          \
		if (!evt)                                                     \
			return 0;                                             \
		__builtin_memset(evt, 0, sizeof(*evt));                       \
		fill_header(&evt->hdr, EVENT_PRIVILEGE);                      \
		evt->syscall_nr = (NR);                                       \
		COPY_ARGS;                                                    \
		bpf_ringbuf_submit(evt, 0);                                   \
		return 0;                                                     \
	} while (0)

SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(105, PRIV_ARGS_1); /* __NR_setuid */
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int tracepoint__syscalls__sys_enter_setgid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(106, PRIV_ARGS_1); /* __NR_setgid */
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int tracepoint__syscalls__sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(113, PRIV_ARGS_2); /* __NR_setreuid */
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int tracepoint__syscalls__sys_enter_setregid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(114, PRIV_ARGS_2); /* __NR_setregid */
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int tracepoint__syscalls__sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(117, PRIV_ARGS_3); /* __NR_setresuid */
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int tracepoint__syscalls__sys_enter_setresgid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(119, PRIV_ARGS_3); /* __NR_setresgid */
}

SEC("tracepoint/syscalls/sys_enter_mount")
int tracepoint__syscalls__sys_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_MOUNT);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MOUNT);

	/* mount(2): args[0]=source, args[1]=target, args[2]=filesystemtype, args[3]=flags */
	evt->arg0 = ctx->args[3]; /* mount flags */

	const char *target = (const char *)ctx->args[1];
	if (target)
		bpf_probe_read_user_str(evt->path, sizeof(evt->path), target);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct process_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_PROCESS_FORK);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROCESS_FORK);
	evt->clone_flags = ctx->args[0];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int tracepoint__syscalls__sys_enter_clone3(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct process_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_PROCESS_FORK);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROCESS_FORK);

	/* P1-7: clone3 receives a userspace pointer to struct clone_args
	 * in args[0] instead of inlining flags as the legacy clone(2) does.
	 * Read just the flags field (first u64 of clone_args) so we don't
	 * fault on truncated structs from older glibc. If the user pointer
	 * is bad we fall back to 0 — matches the legacy zero-flag fallback. */
	void *uargs = (void *)ctx->args[0];
	__u64 flags = 0;
	if (uargs)
		bpf_probe_read_user(&flags, sizeof(flags), uargs);
	evt->clone_flags = flags;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct network_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_NET_CONNECT);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_CONNECT);
	evt->direction = 0;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int tracepoint__syscalls__sys_enter_delete_module(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_MODULE_UNLOAD);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MODULE_UNLOAD);
	evt->arg0 = ctx->args[1];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int tracepoint__syscalls__sys_enter_capset(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_PRIVILEGE);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	/*
	 * capset(2) changes a process's capability sets, so this is a
	 * credential change, not a signal. It kept emitting EVENT_SIGNAL after
	 * the setuid family moved to EVENT_PRIVILEGE, which left the
	 * credential_change row uncreditable from capset and put the event in
	 * a type reserved for kill(2).
	 */
	fill_header(&evt->hdr, EVENT_PRIVILEGE);
	evt->syscall_nr = 126;
	evt->arg0 = ctx->args[0];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int tracepoint__syscalls__sys_enter_prctl(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_PRIVILEGE);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	/* prctl(2): same correction as capset above. */
	fill_header(&evt->hdr, EVENT_PRIVILEGE);
	evt->syscall_nr = 157;
	evt->arg0 = ctx->args[0];
	evt->arg1 = ctx->args[1];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int tracepoint__syscalls__sys_enter_unshare(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_UNSHARE);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_UNSHARE);
	evt->arg0 = ctx->args[0];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int tracepoint__syscalls__sys_enter_madvise(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_MADVISE);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MADVISE);
	evt->arg0 = ctx->args[0];
	evt->arg1 = ctx->args[1];
	evt->arg2 = ctx->args[2];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf_prog, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_BPF_LOAD);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_BPF_LOAD);
	evt->bpf_cmd = (__u32)cmd;
	if (attr)
		evt->bpf_prog_type = BPF_CORE_READ(attr, prog_type);
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("lsm/bpf_map")
int BPF_PROG(lsm_bpf_map_prog, struct bpf_map *map, fmode_t fmode)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_BPF_MAP_ACCESS);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_BPF_MAP_ACCESS);
	evt->bpf_map_id = BPF_CORE_READ(map, id);
	bpf_probe_read_kernel_str(evt->map_name, sizeof(evt->map_name), BPF_CORE_READ(map, name));
	evt->mode = (__u32)fmode;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/cgroup/cgroup_attach_task")
int tp_cgroup_attach(void *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_CGROUP_ATTACH);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_CGROUP_ATTACH);
	bpf_get_current_comm(evt->path, sizeof(evt->path));
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/cgroup/cgroup_mkdir")
int tp_cgroup_mkdir(void *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_CGROUP_MKDIR);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_CGROUP_MKDIR);
	bpf_get_current_comm(evt->path, sizeof(evt->path));
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_seccomp")
int tp_seccomp(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	if ((__u64)ctx->args[0] != 1)
		return 0;
	struct security_event *evt = edr_ringbuf_reserve(&sec_events, sizeof(*evt), EVENT_SECCOMP);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_SECCOMP);
	evt->arg0 = ctx->args[0];
	evt->arg1 = ctx->args[1];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
