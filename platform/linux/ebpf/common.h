/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared event structures and map definitions for EDR eBPF programs.
 * Consumed by both eBPF C programs and the Go userspace agent.
 */
#ifndef __EDR_COMMON_H__
#define __EDR_COMMON_H__

#include <stdbool.h>

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN     512
#define MAX_PATH_LEN     256
#define MAX_DNS_QNAME_LEN 253

enum event_type {
	EVENT_PROCESS_EXEC  = 1,
	EVENT_PROCESS_EXIT  = 2,
	EVENT_PROCESS_FORK  = 3,
	EVENT_FILE_OPEN     = 6,
	EVENT_FILE_WRITE    = 7,
	EVENT_FILE_DELETE   = 8,
	EVENT_FILE_RENAME   = 9,
	EVENT_FILE_CHMOD    = 28,
	EVENT_NET_CONNECT   = 11,
	EVENT_NET_ACCEPT    = 12,
	EVENT_NET_BIND      = 13,
	EVENT_NET_CLOSE     = 14,
	EVENT_MODULE_LOAD   = 22,
	EVENT_MOUNT         = 23,
	EVENT_PTRACE        = 24,
	EVENT_SIGNAL        = 25,
	EVENT_UNSHARE       = 26,
	EVENT_MADVISE       = 27,
	EVENT_BPF_LOAD      = 29,
	EVENT_BPF_MAP_ACCESS = 30,
	EVENT_CGROUP_ATTACH = 31,
	EVENT_CGROUP_MKDIR  = 32,
	EVENT_SECCOMP       = 33,
	EVENT_PROC_MEM_WRITE = 34,
	EVENT_DNS_QUERY     = 35,
};

struct event_header {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u64 timestamp;
	char  comm[TASK_COMM_LEN];
};

struct process_event {
	struct event_header hdr;
	char   filename[MAX_FILENAME_LEN];
	__u32  args_size;
	char   args[MAX_ARGS_LEN];
	__s32  exit_code;
	__u32  child_pid;
	__u64  clone_flags;
};

struct file_event {
	struct event_header hdr;
	char   filename[MAX_FILENAME_LEN];
	__u32  flags;          /* openat: O_*; unlinkat/renameat2: AT_* / rename flags */
	__u32  write_fd;       /* write/pwrite64: fd; otherwise 0 */
	__u32  mode;
	__u32  reserved_align; /* padding before bytes_written; keep zero */
	__u64  bytes_written;
	__u8   sensitive_path;
	__u8   _pad_sensitive[7];
	char   new_filename[MAX_FILENAME_LEN];
};

struct network_event {
	struct event_header hdr;
	__u32 protocol;
	__u32 src_addr;
	__u16 src_port;
	__u32 dst_addr;
	__u16 dst_port;
	__u8  src_addr6[16];
	__u8  dst_addr6[16];
	__u8  is_ipv6;
	__u8  direction;
	char  dns_query[MAX_DNS_QNAME_LEN + 1];
	__u16 dns_qtype;
};

struct security_event {
	struct event_header hdr;
	__u32 syscall_nr;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__u32 bpf_cmd;
	__u32 bpf_prog_type;
	__u32 bpf_map_id;
	__u32 mode;
	char  path[MAX_PATH_LEN];
	char  map_name[64];
};

#endif /* __EDR_COMMON_H__ */
