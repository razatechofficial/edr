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

static __always_inline void fill_header(struct event_header *hdr, __u32 type)
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
	return bpf_map_lookup_elem(&sec_pid_filter, &pid) != NULL;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
 * concrete tracepoint records the canonical x86_64 __NR_* and forwards
 * args[0] (and args[1..2] where meaningful) as the requested IDs.
 */
#define EMIT_PRIVILEGE_EVENT(NR)                                              \
	do {                                                                  \
		if (pid_is_filtered())                                        \
			return 0;                                             \
		struct security_event *evt =                                  \
			bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);    \
		if (!evt)                                                     \
			return 0;                                             \
		__builtin_memset(evt, 0, sizeof(*evt));                       \
		fill_header(&evt->hdr, EVENT_PRIVILEGE);                      \
		evt->syscall_nr = (NR);                                       \
		evt->arg0 = ctx->args[0];                                     \
		evt->arg1 = ctx->args[1];                                     \
		evt->arg2 = ctx->args[2];                                     \
		bpf_ringbuf_submit(evt, 0);                                   \
		return 0;                                                     \
	} while (0)

SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(105); /* __NR_setuid */
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int tracepoint__syscalls__sys_enter_setgid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(106); /* __NR_setgid */
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int tracepoint__syscalls__sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(113); /* __NR_setreuid */
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int tracepoint__syscalls__sys_enter_setregid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(114); /* __NR_setregid */
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int tracepoint__syscalls__sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(117); /* __NR_setresuid */
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int tracepoint__syscalls__sys_enter_setresgid(struct trace_event_raw_sys_enter *ctx)
{
	EMIT_PRIVILEGE_EVENT(119); /* __NR_setresgid */
}

SEC("tracepoint/syscalls/sys_enter_mount")
int tracepoint__syscalls__sys_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct process_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct process_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct network_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MODULE_LOAD);
	evt->arg0 = ctx->args[1];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int tracepoint__syscalls__sys_enter_capset(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_SIGNAL);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_SIGNAL);
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
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
	struct security_event *evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
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
