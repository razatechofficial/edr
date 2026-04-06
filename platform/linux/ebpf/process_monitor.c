// SPDX-License-Identifier: GPL-2.0
// Process execution and lifecycle monitoring for EDR agent.
// Compiled with: clang -O2 -target bpf -D__TARGET_ARCH_x86 -c process_monitor.c -o process_monitor.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define MAX_ARGS_ENTRIES 20

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} pid_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, __u8);
} comm_filter SEC(".maps");

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

static __always_inline bool is_filtered(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (bpf_map_lookup_elem(&pid_filter, &pid))
		return true;

	char comm[TASK_COMM_LEN] = {};
	bpf_get_current_comm(comm, sizeof(comm));
	if (bpf_map_lookup_elem(&comm_filter, comm))
		return true;

	return false;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	if (is_filtered())
		return 0;

	struct process_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROCESS_EXEC);

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);

	const char *const *argv = (const char *const *)ctx->args[1];
	__u32 offset = 0;

	#pragma unroll
	for (int i = 0; i < MAX_ARGS_ENTRIES; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
			break;

		if (offset >= MAX_ARGS_LEN - 1)
			break;

		int ret = bpf_probe_read_user_str(
			&evt->args[offset],
			MAX_ARGS_LEN - offset,
			argp);
		if (ret <= 0)
			break;

		offset += ret;
		if (offset < MAX_ARGS_LEN)
			evt->args[offset - 1] = ' ';
	}

	evt->args_size = offset;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
	if (is_filtered())
		return 0;

	struct process_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROCESS_EXEC);

	/* execveat: args[1] is pathname, args[3] is argv */
	const char *filename = (const char *)ctx->args[1];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);

	const char *const *argv = (const char *const *)ctx->args[3];
	__u32 offset = 0;

	#pragma unroll
	for (int i = 0; i < MAX_ARGS_ENTRIES; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
			break;

		if (offset >= MAX_ARGS_LEN - 1)
			break;

		int ret = bpf_probe_read_user_str(
			&evt->args[offset],
			MAX_ARGS_LEN - offset,
			argp);
		if (ret <= 0)
			break;

		offset += ret;
		if (offset < MAX_ARGS_LEN)
			evt->args[offset - 1] = ' ';
	}

	evt->args_size = offset;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent_pid = ctx->parent_pid;
	if (bpf_map_lookup_elem(&pid_filter, &parent_pid))
		return 0;

	struct process_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROCESS_FORK);

	evt->child_pid = ctx->child_pid;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	if (is_filtered())
		return 0;

	struct process_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROCESS_EXIT);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	evt->exit_code = BPF_CORE_READ(task, exit_code) >> 8;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
