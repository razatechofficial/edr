// SPDX-License-Identifier: GPL-2.0
// Scheduler tracepoint probes (sched_switch / sched_wakeup / sched_migrate_task).

#include "vmlinux.h"
#include "tracepoint_sched_layout.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} sched_events SEC(".maps");

static __always_inline void fill_sched_hdr(struct event_header *hdr, __u32 ev_type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	hdr->type = ev_type;
	hdr->pid = pid_tgid >> 32;
	hdr->ppid = 0;
	hdr->uid = uid_gid & 0xFFFFFFFF;
	hdr->gid = uid_gid >> 32;
	hdr->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

SEC("tracepoint/sched/sched_switch")
int edr_tp_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	struct sched_event *e;

	e = bpf_ringbuf_reserve(&sched_events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_sched_hdr(&e->hdr, EVENT_SCHED_SWITCH);
	e->prev_pid = BPF_CORE_READ(ctx, prev_pid);
	e->next_pid = BPF_CORE_READ(ctx, next_pid);
	e->cpu = bpf_get_smp_processor_id();
	e->runtime_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int edr_tp_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx)
{
	struct sched_event *e;

	e = bpf_ringbuf_reserve(&sched_events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_sched_hdr(&e->hdr, EVENT_SCHED_WAKEUP);
	e->next_pid = BPF_CORE_READ(ctx, pid);
	e->target_cpu = (__u32)BPF_CORE_READ(ctx, target_cpu);
	e->cpu = bpf_get_smp_processor_id();
	e->runtime_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_migrate_task")
int edr_tp_sched_migrate_task(struct trace_event_raw_sched_migrate_task *ctx)
{
	struct sched_event *e;

	e = bpf_ringbuf_reserve(&sched_events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_sched_hdr(&e->hdr, EVENT_SCHED_MIGRATE);
	e->prev_pid = BPF_CORE_READ(ctx, pid);
	e->cpu = (__u32)BPF_CORE_READ(ctx, orig_cpu);
	e->target_cpu = (__u32)BPF_CORE_READ(ctx, dest_cpu);
	e->runtime_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
	return 0;
}
