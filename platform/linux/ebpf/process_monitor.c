// SPDX-License-Identifier: GPL-2.0
//
// P2-1: per-pid metadata scratch map. Process exec / exit handlers
// populate pid_meta with the originating cgroup id so downstream
// network / file handlers can attribute by container without parsing
// task_struct each time. Userspace can also poke entries here to mark
// the agent's own pid so we never self-alert.
// Process execution and lifecycle monitoring for EDR agent.
// Compiled with: clang -O2 -target bpf -D__TARGET_ARCH_x86 -c process_monitor.c -o process_monitor.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

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

/* P2-1: per-pid metadata. See common.h for the struct definition. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct pid_meta);
} pid_meta SEC(".maps");

/* pid_meta_update writes the current cgroup id and timestamp for the
 * calling task. Called from exec/fork/exit handlers so the map stays
 * roughly synchronized with live processes. */
static __always_inline void pid_meta_update(__u32 pid)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct pid_meta meta = {};
	meta.cgroup_id = bpf_get_current_cgroup_id();
	meta.last_seen_ns = bpf_ktime_get_ns();
	/* Preserve flags set by userspace (e.g. agent self-tag) on update. */
	struct pid_meta *existing = bpf_map_lookup_elem(&pid_meta, &pid);
	if (existing) {
		meta.flags = existing->flags;
	}
	(void)task;
	bpf_map_update_elem(&pid_meta, &pid, &meta, BPF_ANY);
}

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

/*
 * capture_argv reads up to 16 argv strings into evt->args, separated by
 * single spaces. The trailing NUL written by bpf_probe_read_user_str is
 * overwritten with a space; the very last space is replaced with a NUL
 * before returning so the buffer is a valid C string. Stops early on
 * NULL argv slot, read failure, or buffer exhaustion. evt->args_size is
 * set to the number of bytes used (excluding the terminating NUL).
 *
 * The args buffer length MAX_ARGS_LEN must be a power of two so the
 * masked offset proves bounded to the BPF verifier.
 */
static __always_inline void capture_argv(struct process_event *evt,
                                         const char *const *argv)
{
	__u32 off = 0;

	if (!argv)
		return;

	#pragma unroll
	for (int i = 0; i < 16; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0)
			break;
		if (!argp)
			break;
		if (off >= MAX_ARGS_LEN - 1)
			break;
		/* Mask to keep the verifier convinced about bounds. */
		__u32 idx = off & (MAX_ARGS_LEN - 1);
		__u32 remaining = MAX_ARGS_LEN - 1 - idx;
		if (remaining < 2)
			break;
		int written = bpf_probe_read_user_str(&evt->args[idx],
		                                      remaining, argp);
		if (written <= 0)
			break;
		off = idx + (__u32)(written - 1);
		if (off >= MAX_ARGS_LEN - 1)
			break;
		evt->args[off & (MAX_ARGS_LEN - 1)] = ' ';
		off++;
	}
	if (off > 0) {
		__u32 last = (off - 1) & (MAX_ARGS_LEN - 1);
		evt->args[last] = '\0';
		evt->args_size = off - 1;
	}
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
	pid_meta_update(evt->hdr.pid);

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);

	/* Full argv capture (up to 16 args), verifier-safe. */
	capture_argv(evt, (const char *const *)ctx->args[1]);

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

	/* Full argv capture (up to 16 args), verifier-safe. */
	capture_argv(evt, (const char *const *)ctx->args[3]);

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

	/* Free the per-pid scratch entry so the map does not bloat. */
	bpf_map_delete_elem(&pid_meta, &evt->hdr.pid);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
