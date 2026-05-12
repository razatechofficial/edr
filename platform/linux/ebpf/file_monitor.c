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

/*
 * P1-6: fd -> path tracking.
 *
 * pending_open_paths stores the filename argument captured at
 * sys_enter_openat (we don't know the fd yet because the syscall hasn't
 * returned). On sys_exit_openat we move the entry into fd_path_map keyed
 * by (pid<<32 | fd) so subsequent write/pwrite/writev events can resolve
 * fd back to a path. sys_enter_close clears the entry so the map does
 * not leak.
 *
 * Each value is a fixed MAX_PATH_LEN buffer. With max_entries=65536 this
 * pins ~16 MiB of kernel memory worst case which is acceptable for an
 * EDR-class agent.
 */
struct fd_path_value {
	char path[MAX_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); /* tgid<<32 | tid */
	__type(value, struct fd_path_value);
} pending_open_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* pid<<32 | fd */
	__type(value, struct fd_path_value);
} fd_path_map SEC(".maps");

static __always_inline __u64 fd_key(__u32 pid, __u32 fd)
{
	return ((__u64)pid << 32) | (__u64)fd;
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

static __always_inline bool pid_is_filtered(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&file_pid_filter, &pid) != NULL;
}

static __always_inline int starts_with(const char *s, const char *pfx)
{
	int i = 0;
#pragma unroll
	for (i = 0; i < 64; i++) {
		char pc = pfx[i];
		if (pc == '\0')
			return 1;
		if (s[i] != pc)
			return 0;
	}
	return 0;
}

static __always_inline void mark_sensitive(struct file_event *evt)
{
	if (starts_with(evt->filename, "/etc/passwd") ||
	    starts_with(evt->filename, "/etc/shadow") ||
	    starts_with(evt->filename, "/etc/sudoers") ||
	    starts_with(evt->filename, "/etc/cron") ||
	    starts_with(evt->filename, "/etc/ld.so.preload") ||
	    starts_with(evt->filename, "/etc/systemd/system")) {
		evt->sensitive_path = 1;
	}
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	/* P1-6: stash the filename for sys_exit_openat to claim once we
	 * know the assigned fd. Keyed by full pid_tgid because two threads
	 * in the same process can open files concurrently. */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct fd_path_value pending = {};
	bpf_probe_read_user_str(pending.path, sizeof(pending.path),
		(const char *)ctx->args[1]);
	bpf_map_update_elem(&pending_open_paths, &pid_tgid, &pending, BPF_ANY);

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_OPEN);

	/* openat(2): args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode */
	__builtin_memcpy(evt->filename, pending.path, sizeof(evt->filename));
	evt->flags = (__u32)ctx->args[2];
	evt->mode  = (__u32)ctx->args[3];
	mark_sensitive(evt);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * sys_exit_openat: take the path stashed by sys_enter_openat and bind
 * it to the (pid, fd) returned by the kernel so that write events can
 * resolve fd back to a filename.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct fd_path_value *pending = bpf_map_lookup_elem(&pending_open_paths, &pid_tgid);
	if (!pending)
		return 0;

	long ret = ctx->ret;
	if (ret >= 0) {
		__u32 pid = pid_tgid >> 32;
		__u64 key = fd_key(pid, (__u32)ret);
		bpf_map_update_elem(&fd_path_map, &key, pending, BPF_ANY);
	}
	bpf_map_delete_elem(&pending_open_paths, &pid_tgid);
	return 0;
}

/*
 * sys_enter_close removes the (pid, fd) entry so the map does not leak
 * stale entries when fds are recycled. We only act on actual close
 * syscalls; the LRU eviction policy is a safety net for missed closes.
 */
SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 key = fd_key(pid, (__u32)ctx->args[0]);
	bpf_map_delete_elem(&fd_path_map, &key);
	return 0;
}

static __always_inline void emit_write_event(__u32 fd, __u64 count)
{
	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_WRITE);

	evt->write_fd = fd;
	evt->bytes_written = count;

	/* P1-6: enrich with filename when fd_path_map has a binding. */
	__u32 pid = evt->hdr.pid;
	__u64 key = fd_key(pid, fd);
	struct fd_path_value *p = bpf_map_lookup_elem(&fd_path_map, &key);
	if (p) {
		__builtin_memcpy(evt->filename, p->path, sizeof(evt->filename));
		mark_sensitive(evt);
	}

	bpf_ringbuf_submit(evt, 0);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	/* write(2): args[0]=fd, args[2]=count */
	emit_write_event((__u32)ctx->args[0], ctx->args[2]);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int tracepoint__syscalls__sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	/* pwrite64(2): args[0]=fd, args[2]=count */
	emit_write_event((__u32)ctx->args[0], ctx->args[2]);
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
	mark_sensitive(evt);

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
	mark_sensitive(evt);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * P1-8: cover the legacy rename(2) and renameat(2) variants. glibc 2.32+
 * routes most callers through renameat2 already, but a non-trivial number
 * of binaries (older containers, statically linked busybox, Go binaries
 * built with older toolchains) still call the legacy syscalls directly.
 * Skipping them creates a blind spot for ransomware reconnaissance and
 * dropper rename activity.
 */
SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_RENAME);

	/* rename(2): args[0]=oldpath, args[1]=newpath */
	const char *oldname = (const char *)ctx->args[0];
	const char *newname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), oldname);
	bpf_probe_read_user_str(evt->new_filename, sizeof(evt->new_filename), newname);
	mark_sensitive(evt);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint__syscalls__sys_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_RENAME);

	/* renameat(2): args[0]=olddfd, args[1]=oldname, args[2]=newdfd, args[3]=newname */
	const char *oldname = (const char *)ctx->args[1];
	const char *newname = (const char *)ctx->args[3];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), oldname);
	bpf_probe_read_user_str(evt->new_filename, sizeof(evt->new_filename), newname);
	mark_sensitive(evt);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt;
	evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_FILE_CHMOD);

	/* fchmodat(2): args[0]=dfd, args[1]=pathname, args[2]=mode, args[3]=flag */
	const char *pathname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), pathname);
	evt->mode = (__u32)ctx->args[2];
	evt->flags = (__u32)ctx->args[3];
	mark_sensitive(evt);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("kprobe/mem_write")
int kprobe_mem_write(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_PROC_MEM_WRITE);
	bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename), "/proc/self/mem");
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
