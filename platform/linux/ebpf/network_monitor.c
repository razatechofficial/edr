// SPDX-License-Identifier: GPL-2.0
// Network connection monitoring for EDR agent.
// Compiled with: clang -O2 -target bpf -D__TARGET_ARCH_x86 -c network_monitor.c -o network_monitor.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define AF_INET  2
#define AF_INET6 10
#define TCP_ESTABLISHED 1
#define TCP_CLOSE       7

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} net_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} net_pid_filter SEC(".maps");

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
	return bpf_map_lookup_elem(&net_pid_filter, &pid) != NULL;
}

static __always_inline int parse_sockaddr(struct network_event *evt,
					  const struct sockaddr *uaddr)
{
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family) < 0)
		return -1;

	if (family == AF_INET) {
		struct sockaddr_in sin = {};
		if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) < 0)
			return -1;
		evt->dst_addr = sin.sin_addr.s_addr;
		evt->dst_port = __builtin_bswap16(sin.sin_port);
		evt->protocol = AF_INET;
		evt->is_ipv6  = 0;
	} else if (family == AF_INET6) {
		struct sockaddr_in6 sin6 = {};
		if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) < 0)
			return -1;
		__builtin_memcpy(evt->dst_addr6, &sin6.sin6_addr, 16);
		evt->dst_port = __builtin_bswap16(sin6.sin6_port);
		evt->protocol = AF_INET6;
		evt->is_ipv6  = 1;
	} else {
		return -1;
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	/* connect(2): args[0]=fd, args[1]=addr, args[2]=addrlen */
	const struct sockaddr *uaddr = (const struct sockaddr *)ctx->args[1];

	struct network_event *evt;
	evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_CONNECT);
	evt->direction = 0; /* outbound */

	if (parse_sockaddr(evt, uaddr) < 0) {
		bpf_ringbuf_discard(evt, 0);
		return 0;
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct network_event *evt;
	evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_ACCEPT);
	evt->direction = 1; /* inbound */

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct network_event *evt;
	evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_ACCEPT);
	evt->direction = 1; /* inbound */

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;

	/* bind(2): args[0]=fd, args[1]=addr, args[2]=addrlen */
	const struct sockaddr *uaddr = (const struct sockaddr *)ctx->args[1];

	struct network_event *evt;
	evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_BIND);
	evt->direction = 1; /* inbound (local bind) */

	if (parse_sockaddr(evt, uaddr) < 0) {
		bpf_ringbuf_discard(evt, 0);
		return 0;
	}

	/* For bind, the parsed address is local (src), not remote (dst). */
	evt->src_addr = evt->dst_addr;
	evt->src_port = evt->dst_port;
	__builtin_memcpy(evt->src_addr6, evt->dst_addr6, 16);
	evt->dst_addr = 0;
	evt->dst_port = 0;
	__builtin_memset(evt->dst_addr6, 0, 16);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_dns_sendto(struct trace_event_raw_sys_enter *ctx)
{
	if (pid_is_filtered())
		return 0;
	const struct sockaddr *uaddr = (const struct sockaddr *)ctx->args[4];
	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_DNS_QUERY);
	evt->direction = 0;
	if (parse_sockaddr(evt, uaddr) < 0) {
		bpf_ringbuf_discard(evt, 0);
		return 0;
	}
	if (evt->dst_port != 53) {
		bpf_ringbuf_discard(evt, 0);
		return 0;
	}
	const unsigned char *buf = (const unsigned char *)ctx->args[1];
	unsigned char qname[MAX_DNS_QNAME_LEN + 1] = {};
	bpf_probe_read_user(qname, sizeof(qname), buf + 12);
	bpf_probe_read_kernel_str(evt->dns_query, sizeof(evt->dns_query), qname);
	evt->dns_qtype = 1;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * Kernel-side enrichment: tcp_v4_connect runs inside the kernel after the
 * sockaddr has been validated and the local source port assigned, so this
 * gives us a fully resolved 4-tuple that the syscall tracepoint cannot.
 * Failures inside CO-RE reads are tolerated; we just emit what we have.
 */
SEC("kprobe/tcp_v4_connect")
int kp_tcp_v4_connect(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_CONNECT);
	evt->direction = 0;
	evt->protocol  = AF_INET;
	evt->is_ipv6   = 0;

	__u32 saddr = 0, daddr = 0;
	__u16 sport = 0, dport = 0;
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	evt->src_addr = saddr;
	evt->dst_addr = daddr;
	evt->src_port = sport;
	evt->dst_port = __builtin_bswap16(dport);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * tcp_v6_connect enriches outbound IPv6 connects. We capture the assigned
 * source port and remote port from kernel socket state; address extraction is
 * intentionally deferred for broad kernel compatibility in the fallback lane.
 */
SEC("kprobe/tcp_v6_connect")
int kp_tcp_v6_connect(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_CONNECT);
	evt->direction = 0;
	evt->protocol  = AF_INET6;
	evt->is_ipv6   = 1;

	__u16 sport = 0, dport = 0;
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	evt->src_port = sport;
	evt->dst_port = __builtin_bswap16(dport);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * udp_sendmsg is the single kernel entry-point for both sendto(2) and
 * sendmsg(2) on UDP sockets. Hooking it gives DNS query visibility even
 * when an application uses sendmsg with iov (which the syscall tracepoint
 * for sendto misses). We do not parse the DNS qname here - the syscall
 * tracepoint above does that - this kprobe only emits a lightweight
 * EVENT_DNS_QUERY breadcrumb so userland can correlate.
 */
SEC("kprobe/udp_sendmsg")
int kp_udp_sendmsg(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	__u16 dport_be = 0;
	BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
	__u16 dport = __builtin_bswap16(dport_be);
	if (dport != 53)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_DNS_QUERY);
	evt->direction = 0;
	evt->protocol  = AF_INET;
	evt->dst_port  = dport;

	__u32 daddr = 0;
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	evt->dst_addr = daddr;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * tcp_close fires once per closed TCP connection (both client and server),
 * giving an accurate connection-end signal that userland correlators use to
 * compute connection duration and tear down lineage state.
 */
SEC("kprobe/tcp_close")
int kp_tcp_close(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_CLOSE);
	evt->direction = 0;
	evt->protocol  = AF_INET;

	__u32 saddr = 0, daddr = 0;
	__u16 sport = 0, dport = 0;
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	evt->src_addr = saddr;
	evt->dst_addr = daddr;
	evt->src_port = sport;
	evt->dst_port = __builtin_bswap16(dport);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/*
 * inet_sock_set_state gives L4 state transition visibility for both IPv4/IPv6.
 * We emit connect-like events on ESTABLISHED and close events on CLOSE.
 */
SEC("kprobe/inet_sock_set_state")
int kp_inet_sock_set_state(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	int oldstate = (int)PT_REGS_PARM2(ctx);
	int newstate = (int)PT_REGS_PARM3(ctx);
	if (oldstate == newstate)
		return 0;
	if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, newstate == TCP_CLOSE ? EVENT_NET_CLOSE : EVENT_NET_CONNECT);
	evt->direction = 0;

	__u16 family = 0;
	__u16 sport = 0, dport = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	evt->src_port = sport;
	evt->dst_port = __builtin_bswap16(dport);
	if (family == AF_INET6) {
		evt->protocol = AF_INET6;
		evt->is_ipv6 = 1;
	} else {
		evt->protocol = AF_INET;
		evt->is_ipv6 = 0;
		__u32 saddr = 0, daddr = 0;
		BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
		evt->src_addr = saddr;
		evt->dst_addr = daddr;
	}
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
