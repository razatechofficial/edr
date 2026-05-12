#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef unsigned int fmode_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef int pid_t;

struct trace_event_raw_sys_enter {
	__u64 unused;
	__u64 args[6];
};

struct trace_event_raw_sched_process_fork {
	char _pad0[8];
	pid_t parent_pid;
	pid_t child_pid;
};

struct trace_event_raw_sched_process_template {
	char _pad0[8];
};

/* Tracepoint raw payloads (layout follows common 5.15–6.x x86_64 sched events). */
struct trace_event_raw_sched_switch {
	char _pad0[8];
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

struct trace_event_raw_sched_wakeup {
	char _pad0[8];
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
};

struct trace_event_raw_sched_migrate_task {
	char _pad0[8];
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
};

struct task_struct {
	struct task_struct *real_parent;
	__u32 tgid;
	__s32 exit_code;
};

struct sockaddr {
	__u16 sa_family;
	char sa_data[14];
};

struct in_addr {
	__u32 s_addr;
};

struct in6_addr {
	unsigned char s6_addr[16];
};

struct sockaddr_in {
	__u16 sin_family;
	__u16 sin_port;
	struct in_addr sin_addr;
	unsigned char sin_zero[8];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__u16 sin6_port;
	__u32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct qstr {
	const char *name;
};

struct dentry {
	struct qstr d_name;
};

struct iattr {
	unsigned int ia_valid;
	unsigned int ia_mode;
};

struct path {
	struct dentry *dentry;
};

struct file {
	struct path f_path;
};

struct bpf_map {
	__u32 id;
	char name[16];
};

struct linux_binprm {
	struct file *file;
};

struct socket {
	int _dummy;
};

struct kernel_siginfo {
	int _dummy;
};

struct cred {
	int _dummy;
};

union bpf_attr {
	__u32 prog_type;
};

#define EDR_SCHED_TRACEPOINT_LAYOUTS
