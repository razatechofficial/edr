// SPDX-License-Identifier: GPL-2.0
// File system operation monitoring for EDR agent.
// Compiled with: clang -O2 -target bpf -D__TARGET_ARCH_x86 -c file_monitor.c -o file_monitor.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} file_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} file_pid_filter SEC(".maps");

/* Prefix match on monitored directories. Key is a null-terminated path prefix. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, __u8);
} path_filter SEC(".maps");

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
	return bpf_map_lookup_elem(&file_pid_filter, &pid) != NULL;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_OPEN);

	/* openat(2): args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode */
	const char *filename = (const char *)ctx->args[1];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);
	evt->flags = (__u32)ctx->args[2];
	evt->mode  = (__u32)ctx->args[3];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_WRITE);

	/* write(2): args[0]=fd, args[2]=count */
	evt->flags = (__u32)ctx->args[0];
	evt->bytes_written = ctx->args[2];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int tracepoint__syscalls__sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_WRITE);

	/* pwrite64(2): args[0]=fd, args[2]=count */
	evt->flags = (__u32)ctx->args[0];
	evt->bytes_written = ctx->args[2];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_DELETE);

	/* unlinkat(2): args[0]=dfd, args[1]=pathname, args[2]=flags */
	const char *pathname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), pathname);
	evt->flags = (__u32)ctx->args[2];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_RENAME);

	/* renameat2(2): args[0]=olddfd, args[1]=oldname, args[2]=newdfd, args[3]=newname, args[4]=flags */
	const char *oldname = (const char *)ctx->args[1];
	const char *newname = (const char *)ctx->args[3];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), oldname);
	bpf_probe_read_user_str(evt->new_filename, sizeof(evt->new_filename), newname);
	evt->flags = (__u32)ctx->args[4];

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
