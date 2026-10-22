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

#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
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
	EVENT_SCHED_SWITCH  = 36,
	EVENT_SCHED_WAKEUP  = 37,
	EVENT_SCHED_MIGRATE = 38,
	/* BPF LSM FIM hooks (userspace-gated by policy.LSMFimEvents). */
	EVENT_LSM_FIM_UNLINK  = 39,
	EVENT_LSM_FIM_RENAME  = 40,
	EVENT_LSM_FIM_SETATTR = 41,
	/*
	 * Privilege-change syscalls (setuid/setgid family). Previously these
	 * tracepoints emitted EVENT_SIGNAL which is reserved for kill(2) and
	 * obscured downstream rules. EVENT_PRIVILEGE carries the new UID/GID
	 * in security_event.arg0 and the syscall number in syscall_nr.
	 */
	EVENT_PRIVILEGE       = 42,
	/*
	 * delete_module(2) used to emit EVENT_MODULE_LOAD, so the capability
	 * report's module_unload row could never be credited however many
	 * modules were removed. Its own type makes the two distinguishable.
	 */
	EVENT_MODULE_UNLOAD   = 43,
	/*
	 * tls_sni_monitor.c used to emit EVENT_NET_CONNECT, which credited
	 * every ClientHello to network_connect and left tls_metadata dark.
	 */
	EVENT_TLS_CLIENT_HELLO = 44,
};

struct edr_event_hdr {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u64 timestamp;
	char  comm[TASK_COMM_LEN];
};

struct process_event {
	struct edr_event_hdr hdr;
	char   filename[MAX_FILENAME_LEN];
	__u32  args_size;
	char   args[MAX_ARGS_LEN];
	__s32  exit_code;
	__u32  child_pid;
	__u64  clone_flags;
};

struct file_event {
	struct edr_event_hdr hdr;
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
	struct edr_event_hdr hdr;
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
	struct edr_event_hdr hdr;
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

/* Scheduler tracepoint samples (high volume; userspace gated by policy). */
struct sched_event {
	struct edr_event_hdr hdr;
	__u32 prev_pid;
	__u32 next_pid;
	__u32 cpu;
	__u32 target_cpu;
	__u64 runtime_ns;
};

/*
 * pid_meta is short-lived per-pid scratch used to enrich events with
 * data computed in handlers that run earlier in the pipeline. We index
 * by pid (32-bit) and store a small fixed struct with the cgroup id and
 * a "last seen" timestamp. Userspace can also write entries here to
 * tag specific pids (e.g. "this is the agent" so we never alert on
 * ourselves). The map is sized to a generous 16k pids and uses
 * BPF_F_NO_PREALLOC so cold cores do not pin memory.
 */
struct pid_meta {
	__u64 cgroup_id;
	__u64 last_seen_ns;
	__u32 flags;      /* bit 0: this is the EDR agent */
	__u32 _pad;
};

/*
 * ---------------------------------------------------------------------------
 * Kernel-side event accounting (event_stats)
 * ---------------------------------------------------------------------------
 *
 * Every bpf_ringbuf_reserve() call site in this tree used to read:
 *
 *	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
 *	if (!evt)
 *		return 0;
 *
 * A reserve returns NULL when the ring buffer has no room, which is the one
 * loss on the whole path that userspace cannot see: the record never left the
 * kernel, so the driver's EventsDropped, the RingBuffer's Dropped and the
 * capability report's events_observed all stay at zero while events are being
 * thrown away. On a busy host that is silent data loss in a security product.
 * Worse, "no event arrived" then reads identically whether the hook never
 * fired, a filter dropped the event, or the buffer was full.
 *
 * event_stats makes the three distinguishable. It is a per-CPU array indexed
 * by enum event_type, with one counter per outcome:
 *
 *	submitted      — reserve succeeded and the record was filled in
 *	reserve_failed — the ring buffer was full; the record was lost here
 *
 * and a companion map, filter_stats, counts the events an in-kernel pid filter
 * dropped before any reserve was attempted. Between them, a type with zero of
 * all three is a hook that did not fire, which is a different fault with a
 * different fix.
 *
 * Per-CPU so the counters cost a lookup and a non-atomic increment, and so
 * two CPUs in the same handler do not contend. Userspace sums across CPUs.
 *
 * Indexed by event type rather than by program or by ring buffer because that
 * is the dimension an operator and a test failure both need: it names the
 * stream that is losing records. Userspace maps event types to ring buffers
 * when it needs the per-buffer total (for sizing) and to capability categories
 * when it needs the per-category total (for the report).
 *
 * The helpers live in this header because every program in every file needs
 * them. The maps themselves are defined in one file and externed in the rest,
 * which is how file_monitor.c and lsm_fim.c already share file_events.
 *
 * Guarded on SEC because this header is also read by tooling that does not
 * include bpf_helpers.h; without the helper macros there is nothing to define.
 */
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif

/*
 * One slot per event type. The largest type above is EVENT_TLS_CLIENT_HELLO
 * (44); 64 slots leave room to add types without touching the loader, which
 * refuses an object whose map geometry it does not expect.
 */
#define EDR_EVENT_TYPE_MAX 64

struct edr_event_stats {
	__u64 submitted;
	__u64 reserve_failed;
};

/*
 * Subsystem ids for filter_stats. One per .c file that has a pid filter,
 * because the filter is pid-based and identical for every event type in the
 * file: counting it per subsystem says which filter is eating records without
 * needing the event type at a site that has not decided one yet.
 */
enum edr_subsystem {
	EDR_SUBSYS_PROCESS  = 0,
	EDR_SUBSYS_FILE     = 1,
	EDR_SUBSYS_NETWORK  = 2,
	EDR_SUBSYS_SECURITY = 3,
	EDR_SUBSYS_FIM      = 4,
	EDR_SUBSYS_MAX      = 8,
};

#ifdef SEC

/*
 * Defined in exactly one translation unit and referenced as extern from the
 * rest. libbpf's static linker takes one definition plus extern references;
 * two definitions of one map name is a link error, not a merge. It is the same
 * arrangement file_monitor.c and lsm_fim.c already use for file_events.
 *
 * process_monitor.c defines EDR_SHARED_MAPS_OWNER before including this
 * header. Which file owns them does not matter, only that one does.
 */
#ifdef EDR_SHARED_MAPS_OWNER

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EDR_EVENT_TYPE_MAX);
	__type(key, __u32);
	__type(value, struct edr_event_stats);
} event_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EDR_SUBSYS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} filter_stats SEC(".maps");

#else

extern struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EDR_EVENT_TYPE_MAX);
	__type(key, __u32);
	__type(value, struct edr_event_stats);
} event_stats;

extern struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EDR_SUBSYS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} filter_stats;

#endif /* EDR_SHARED_MAPS_OWNER */

static __always_inline struct edr_event_stats *edr_stats_slot(__u32 type)
{
	if (type >= EDR_EVENT_TYPE_MAX)
		return NULL;
	return bpf_map_lookup_elem(&event_stats, &type);
}

/*
 * edr_stat_filtered records an event one of the in-kernel pid filters dropped.
 *
 * Called from inside the pid_is_filtered() helpers, so every program in a file
 * is counted without a per-call-site change and without needing an event type
 * at a point where some handlers have not yet decided one.
 */
static __always_inline void edr_stat_filtered(__u32 subsys)
{
	__u64 *n;

	if (subsys >= EDR_SUBSYS_MAX)
		return;
	n = bpf_map_lookup_elem(&filter_stats, &subsys);
	if (n)
		(*n)++;
}

/*
 * edr_ringbuf_reserve is bpf_ringbuf_reserve with the outcome counted.
 *
 * It takes the event type the caller is about to write so a failure can be
 * attributed to a stream rather than to the object as a whole. Inlined, so the
 * verifier still sees a constant size and a directly referenced map, which is
 * what bpf_ringbuf_reserve requires.
 */
static __always_inline void *edr_ringbuf_reserve(void *ring, __u64 size, __u32 type)
{
	void *rec = bpf_ringbuf_reserve(ring, size, 0);
	struct edr_event_stats *s = edr_stats_slot(type);

	if (s) {
		if (rec)
			s->submitted++;
		else
			s->reserve_failed++;
	}
	return rec;
}

#endif /* SEC */

#endif /* __EDR_COMMON_H__ */
