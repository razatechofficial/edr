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

SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_SIGNAL);

	/* setuid(2): args[0]=uid */
	evt->syscall_nr = 105; /* __NR_setuid on x86_64 */
	evt->arg0 = ctx->args[0];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int tracepoint__syscalls__sys_enter_setgid(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct security_event *evt;
	evt = bpf_ringbuf_reserve(&sec_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_SIGNAL);

	/* setgid(2): args[0]=gid */
	evt->syscall_nr = 106; /* __NR_setgid on x86_64 */
	evt->arg0 = ctx->args[0];

	bpf_ringbuf_submit(evt, 0);
	return 0;
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

char _license[] SEC("license") = "GPL";
