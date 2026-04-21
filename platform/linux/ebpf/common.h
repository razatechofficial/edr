/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared event structures and map definitions for EDR eBPF programs.
 * Consumed by both eBPF C programs and the Go userspace agent.
 */
#ifndef __EDR_COMMON_H__
#define __EDR_COMMON_H__

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN     512
#define MAX_PATH_LEN     256

enum event_type {
	EVENT_PROCESS_EXEC  = 1,
	EVENT_PROCESS_EXIT  = 2,
	EVENT_PROCESS_FORK  = 3,
	EVENT_FILE_OPEN     = 6,
	EVENT_FILE_WRITE    = 7,
	EVENT_FILE_DELETE   = 8,
	EVENT_FILE_RENAME   = 9,
	EVENT_NET_CONNECT   = 11,
	EVENT_NET_ACCEPT    = 12,
	EVENT_NET_BIND      = 13,
	EVENT_MODULE_LOAD   = 22,
	EVENT_MOUNT         = 23,
	EVENT_PTRACE        = 24,
	EVENT_SIGNAL        = 25,
	EVENT_UNSHARE       = 26,
	EVENT_MADVISE       = 27,
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
	__u32  flags;
	__u32  mode;
	__u64  bytes_written;
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
};

struct security_event {
	struct event_header hdr;
	__u32 syscall_nr;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	char  path[MAX_PATH_LEN];
};

#endif /* __EDR_COMMON_H__ */
