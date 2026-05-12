#pragma once

/* sched_wakeup is sometimes only forward-declared in BTF vmlinux.h. */
#ifndef EDR_SCHED_TRACEPOINT_LAYOUTS

struct trace_event_raw_sched_wakeup {
	char _pad0[8];
	char comm[16];
	pid_t pid;
	int prio;
	int success;
	int target_cpu;
};

#endif /* EDR_SCHED_TRACEPOINT_LAYOUTS */
