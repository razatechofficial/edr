// SPDX-License-Identifier: GPL-2.0
// BPF LSM file-integrity telemetry (observe-only; does not deny).
// Merged into edr.bpf.o; programs named fim_* are attached via AttachLSM in userspace.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Merged with file_monitor.c by llvm-link / bpftool gen object */
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

SEC("lsm/path_unlink")
int BPF_PROG(fim_path_unlink, struct path *dir, struct dentry *dentry)
{
	(void)dir;
	if (pid_is_filtered())
		return 0;

	struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_LSM_FIM_UNLINK);

	const unsigned char *nm = BPF_CORE_READ(dentry, d_name.name);
	if (nm)
		bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename), nm);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(fim_path_rename, struct path *old_dir, struct dentry *old_dentry,
	     struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	(void)old_dir;
	(void)new_dir;
	if (pid_is_filtered())
		return 0;

	struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_LSM_FIM_RENAME);

	const unsigned char *onm = BPF_CORE_READ(old_dentry, d_name.name);
	if (onm)
		bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename), onm);

	const unsigned char *nnm = BPF_CORE_READ(new_dentry, d_name.name);
	if (nnm)
		bpf_probe_read_kernel_str(evt->new_filename, sizeof(evt->new_filename), nnm);
	evt->flags = flags;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(fim_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	if (pid_is_filtered())
		return 0;

	struct file_event *evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_LSM_FIM_SETATTR);

	const unsigned char *nm = BPF_CORE_READ(dentry, d_name.name);
	if (nm)
		bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename), nm);

	__u32 valid = BPF_CORE_READ(attr, ia_valid);
	__u32 mode = BPF_CORE_READ(attr, ia_mode);
	evt->mode = mode;
	evt->flags = valid;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
