// SPDX-License-Identifier: GPL-2.0
// Lightweight TLS ClientHello/SNI monitor stub for Linux eBPF.
// Emits EVENT_NET_CONNECT with dns_query carrying a best-effort SNI prefix.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define AF_INET 2
#define AF_INET6 10

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} tls_events SEC(".maps");

// Bound parser budget to keep verifier/runtime costs predictable.
#define TLS_PARSE_BUDGET 256

static __always_inline void fill_header_tls(struct edr_event_hdr *hdr, __u32 type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	hdr->type = type;
	hdr->pid = pid_tgid >> 32;
	hdr->uid = uid_gid & 0xFFFFFFFF;
	hdr->gid = uid_gid >> 32;
	hdr->timestamp = bpf_ktime_get_ns();
	hdr->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

// Minimal probe: if first bytes look like TLS handshake record + ClientHello,
// copy a bounded printable slice into dns_query as an SNI surrogate stub.
SEC("kprobe/tcp_sendmsg")
int kp_tls_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	if (!sk || !msg)
		return 0;

	struct iov_iter iter = {};
	BPF_CORE_READ_INTO(&iter, msg, msg_iter);
	if (iter.count < 6)
		return 0;

	const struct iovec *iov = NULL;
	BPF_CORE_READ_INTO(&iov, msg, msg_iter.__iov);
	if (!iov)
		return 0;
	void *base = NULL;
	BPF_CORE_READ_INTO(&base, iov, iov_base);
	__u64 iov_len = 0;
	BPF_CORE_READ_INTO(&iov_len, iov, iov_len);
	if (!base || iov_len < 6)
		return 0;

	unsigned char hdr[6] = {};
	if (bpf_probe_read_user(hdr, sizeof(hdr), base) < 0)
		return 0;
	// TLS record handshake + ClientHello.
	if (hdr[0] != 0x16 || hdr[5] != 0x01)
		return 0;

	struct network_event *evt = bpf_ringbuf_reserve(&tls_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	__builtin_memset(evt, 0, sizeof(*evt));
	fill_header_tls(&evt->hdr, EVENT_NET_CONNECT);
	evt->direction = 0;

	__u16 family = 0, sport = 0, dport = 0;
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

	// Stub extraction: bounded, printable prefix as placeholder until full parser.
	unsigned char buf[TLS_PARSE_BUDGET] = {};
	__u32 n = iov_len < TLS_PARSE_BUDGET ? (__u32)iov_len : TLS_PARSE_BUDGET;
	if (bpf_probe_read_user(buf, n, base) == 0) {
		int j = 0;
		#pragma unroll
		for (int i = 0; i < 64; i++) {
			if (i >= n || j >= MAX_DNS_QNAME_LEN)
				break;
			unsigned char c = buf[i];
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			    (c >= '0' && c <= '9') || c == '.' || c == '-') {
				evt->dns_query[j++] = c;
			}
		}
	}
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
