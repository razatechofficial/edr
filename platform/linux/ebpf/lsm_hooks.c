// SPDX-License-Identifier: GPL-2.0
// BPF LSM hooks for security enforcement.
// Requires kernel 5.7+ with BPF_LSM enabled (CONFIG_BPF_LSM=y).
// Compiled with: clang -O2 -target bpf -D__TARGET_ARCH_x86 -c lsm_hooks.c -o lsm_hooks.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define EPERM 1

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} lsm_events SEC(".maps");

/* Deny-list keyed by executable path. Non-null value means deny. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, __u8);
} exec_deny_list SEC(".maps");

/* Deny-list keyed by file path prefix. Non-null value means deny opens. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, __u8);
} file_deny_list SEC(".maps");

/* Deny-list keyed by destination IPv4 address. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} connect_deny_list SEC(".maps");

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

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
	char path[MAX_PATH_LEN] = {};
	const unsigned char *fpath = 0;

	BPF_CORE_READ_INTO(&fpath, bprm, file, f_path.dentry, d_name.name);
	if (!fpath)
		return 0;
	bpf_probe_read_kernel_str(path, sizeof(path), (const char *)fpath);

	if (bpf_map_lookup_elem(&exec_deny_list, path)) {
		struct security_event *evt;
		evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
		if (evt) {
			__builtin_memset(evt, 0, sizeof(*evt));
			fill_header(&evt->hdr, EVENT_PROCESS_EXEC);
			__builtin_memcpy(evt->path, path, MAX_PATH_LEN);
			bpf_ringbuf_submit(evt, 0);
		}
		return -EPERM;
	}

	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
	char path[MAX_PATH_LEN] = {};
	const unsigned char *fpath = 0;

	BPF_CORE_READ_INTO(&fpath, file, f_path.dentry, d_name.name);
	if (!fpath)
		return 0;
	bpf_probe_read_kernel_str(path, sizeof(path), (const char *)fpath);

	if (bpf_map_lookup_elem(&file_deny_list, path)) {
		struct security_event *evt;
		evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
		if (evt) {
			__builtin_memset(evt, 0, sizeof(*evt));
			fill_header(&evt->hdr, EVENT_FILE_OPEN);
			__builtin_memcpy(evt->path, path, MAX_PATH_LEN);
			bpf_ringbuf_submit(evt, 0);
		}
		return -EPERM;
	}

	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	__u16 family = BPF_CORE_READ(address, sa_family);

	if (family != 2) /* AF_INET */
		return 0;

	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	__u32 addr = BPF_CORE_READ(sin, sin_addr.s_addr);

	if (bpf_map_lookup_elem(&connect_deny_list, &addr)) {
		struct network_event *evt;
		evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
		if (evt) {
			__builtin_memset(evt, 0, sizeof(*evt));
			fill_header(&evt->hdr, EVENT_NET_CONNECT);
			evt->dst_addr  = addr;
			evt->dst_port  = __builtin_bswap16(BPF_CORE_READ(sin, sin_port));
			evt->direction = 0;
			bpf_ringbuf_submit(evt, 0);
		}
		return -EPERM;
	}

	return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred)
{
	struct security_event *evt;
	evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_SIGNAL);

	evt->arg0 = (__u64)sig;
	evt->arg1 = (__u64)BPF_CORE_READ(p, tgid);
	evt->arg2 = (__u64)BPF_CORE_READ(p, real_parent, tgid);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(lsm_kernel_module_request, char *kmod_name)
{
	struct security_event *evt;
	evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_MODULE_LOAD);
	if (kmod_name)
		bpf_probe_read_kernel_str(evt->path, sizeof(evt->path), kmod_name);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
