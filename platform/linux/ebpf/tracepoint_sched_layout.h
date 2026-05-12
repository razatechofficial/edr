#pragma once

/* Sched tracepoint raw layouts when vmlinux BTF only forward-declares them. */
#ifndef EDR_SCHED_TRACEPOINT_LAYOUTS

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
	int success;
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

#endif /* EDR_SCHED_TRACEPOINT_LAYOUTS */
