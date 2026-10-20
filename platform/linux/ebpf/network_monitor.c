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

/*
 * Inbound connections are reported from inet_csk_accept's return, not from
 * the accept(2) and accept4(2) entry tracepoints that used to sit here.
 *
 * Those two reserved a slot, memset it, filled the header and submitted,
 * with every address and port left at zero — one event per inbound
 * connection carrying no information about the connection. The reason they
 * never parsed a sockaddr is not an oversight that a parse_sockaddr() call
 * would fix: accept(2)'s addr argument is an *output* parameter. At
 * sys_enter the kernel has not written it yet, so it points at
 * uninitialised userspace memory, and a great many callers pass NULL
 * because they do not want the peer address at all. There is nothing to
 * read at syscall entry.
 *
 * Reading it at sys_exit would work — stash the user pointer at entry,
 * read it back at exit, the way file_monitor.c carries a path from
 * sys_enter_openat to sys_exit_openat — but it costs a correlation map and
 * still only sees what the caller asked the kernel to write.
 *
 * inet_csk_accept returns the newly established struct sock *, which holds
 * both ends of the connection in kernel memory regardless of what the
 * caller passed. One kretprobe, no correlation map, and the addresses are
 * the kernel's own rather than a copy in a userspace buffer. It is also
 * what every other tool that traces inbound TCP hooks.
 *
 * The trade is that this is TCP only: inet_csk_accept does not run for an
 * AF_UNIX accept, so a unix-socket accept is no longer reported. It was
 * previously reported as an event with zeroed addresses, which said only
 * that some process accepted something — and tcp_close, inet_sock_set_state
 * and the bind tracepoint are all equally silent about unix sockets, so the
 * blind spot is the file's, not this program's.
 *
 * The field reads below are deliberately identical to kp_inet_sock_set_state's:
 * for an accepted socket skc_rcv_saddr/skc_num are the local (server) end and
 * skc_daddr/skc_dport the remote (client) end, and IPv6 addresses are left
 * zero with protocol set to AF_INET6 rather than read, matching what the rest
 * of this file does today.
 */
SEC("kretprobe/inet_csk_accept")
int kretp_inet_csk_accept(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
	if (!sk)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_NET_ACCEPT);
	evt->direction = 1; /* inbound */

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
	/*
	 * Preserve the raw DNS wire bytes of the Question section so the
	 * Go-side decoder can parse the label-length-prefixed QNAME and the
	 * QTYPE that follows it. Using bpf_probe_read_user_str / kernel_str
	 * here would truncate the wire bytes at the first non-printable byte
	 * (each label-length prefix is non-printable and the root label is
	 * a NUL terminator). Use raw bytes via bpf_probe_read_user instead.
	 */
	bpf_probe_read_user(evt->dns_query, sizeof(evt->dns_query), buf + 12);
	/*
	 * Best-effort kernel-side QTYPE extraction: walk the label chain in
	 * a bounded loop until we hit the root NUL or a compression pointer.
	 * Userspace re-derives QTYPE from the raw bytes and treats this as
	 * an authoritative hint; this saves a re-walk for the common case.
	 */
	__u16 qtype = 0;
	int off = 0;
	for (int step = 0; step < 32; step++) {
		if (off >= (int)sizeof(evt->dns_query))
			break;
		unsigned char b = evt->dns_query[off];
		if (b == 0) {
			if (off + 2 < (int)sizeof(evt->dns_query))
				qtype = ((__u16)evt->dns_query[off + 1] << 8) |
				        (__u16)evt->dns_query[off + 2];
			break;
		}
		if ((b & 0xC0) == 0xC0) {
			/* Compression pointer: 2 bytes total; treat as end. */
			off += 2;
			if (off + 1 < (int)sizeof(evt->dns_query))
				qtype = ((__u16)evt->dns_query[off] << 8) |
				        (__u16)evt->dns_query[off + 1];
			break;
		}
		off += (int)b + 1;
	}
	evt->dns_qtype = qtype != 0 ? qtype : 1;
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
 * tcp_v6_connect captures the full 16-byte IPv6 source/destination
 * addresses and ports from the kernel sock state (P1-5). The previous
 * implementation only captured ports; addresses were left zero which
 * produced "::" for every IPv6 connect on the userspace side. We read
 * dst from sin6_addr (passed in as PARM2) and src from
 * sk->__sk_common.skc_v6_rcv_saddr, both via BPF CORE so the program
 * remains portable across kernel versions.
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

	/* Source: connected socket carries the local IPv6 in
	 * __sk_common.skc_v6_rcv_saddr. */
	BPF_CORE_READ_INTO(&evt->src_addr6, sk, __sk_common.skc_v6_rcv_saddr);

	/* Destination: tcp_v6_connect(struct sock *, struct sockaddr *uaddr, int)
	 * - PARM2 is a kernel pointer to struct sockaddr_in6 holding the dest. */
	struct sockaddr_in6 *uaddr = (struct sockaddr_in6 *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		struct in6_addr dst6 = {};
		bpf_probe_read_kernel(&dst6, sizeof(dst6), &uaddr->sin6_addr);
		__builtin_memcpy(evt->dst_addr6, &dst6, 16);
		__u16 ndport = 0;
		bpf_probe_read_kernel(&ndport, sizeof(ndport), &uaddr->sin6_port);
		if (ndport != 0)
			evt->dst_port = __builtin_bswap16(ndport);
	}

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
 * P2-4: DNS response visibility. udp_recvmsg is the kernel entry point
 * that fills the userspace buffer with the DNS reply. We hook it as a
 * kprobe AND a kretprobe — the kprobe stashes the sk pointer so the
 * kretprobe can examine source port (53 for DNS) and emit an
 * EVENT_DNS_QUERY with direction=1 (inbound). The reply body itself
 * lives in the application buffer which we cannot reliably read from
 * udp_recvmsg's kernel-side path; userspace correlates with the
 * preceding query by 4-tuple. This is enough to detect cases where a
 * DNS answer arrives without a matching query (e.g. cache poisoning
 * probes, off-path DNS NXDOMAIN reflection).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64); /* pid_tgid */
	__type(value, __u64); /* sock pointer */
} udp_recv_pending SEC(".maps");

SEC("kprobe/udp_recvmsg")
int kp_udp_recvmsg(struct pt_regs *ctx)
{
	if (pid_is_filtered())
		return 0;
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;
	bpf_map_update_elem(&udp_recv_pending, &pid_tgid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretp_udp_recvmsg(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&udp_recv_pending, &pid_tgid);
	if (!skp)
		return 0;
	bpf_map_delete_elem(&udp_recv_pending, &pid_tgid);

	long ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;

	struct sock *sk = (struct sock *)(*skp);
	__u16 sport_be = 0;
	BPF_CORE_READ_INTO(&sport_be, sk, __sk_common.skc_dport);
	__u16 sport = __builtin_bswap16(sport_be);
	if (sport != 53)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header(&evt->hdr, EVENT_DNS_QUERY);
	evt->direction = 1; /* inbound DNS reply */
	evt->protocol  = AF_INET;
	evt->src_port  = sport;

	__u32 saddr = 0;
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_daddr);
	evt->src_addr = saddr;

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
