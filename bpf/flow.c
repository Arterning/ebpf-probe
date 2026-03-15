// SPDX-License-Identifier: GPL-2.0
//
// TCP connection tracker — hooks sock:inet_sock_set_state tracepoint.
// Uses the stable tracepoint ABI (no vmlinux.h required).
// Requires kernel >= 5.8 for BPF_MAP_TYPE_RINGBUF.
//
// Build: see Makefile (clang + libbpf-dev).

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define AF_INET         2
#define IPPROTO_TCP     6
#define TCP_ESTABLISHED 1
#define TASK_COMM_LEN   16

// Stable layout of sock:inet_sock_set_state tracepoint context.
// Validated against kernels 5.4 – 6.8.
// Source: include/trace/events/sock.h  +  debugfs format file.
struct sock_state_ctx {
	__u64        _common;      // 8 bytes: type(2)+flags(1)+preempt(1)+pid(4)
	const void  *skaddr;       // offset  8
	int          oldstate;     // offset 16
	int          newstate;     // offset 20
	__u16        sport;        // offset 24
	__u16        dport;        // offset 26
	__u16        family;       // offset 28
	__u16        protocol;     // offset 30
	__u8         saddr[4];     // offset 32  IPv4 source
	__u8         daddr[4];     // offset 36  IPv4 dest
	__u8         saddr_v6[16]; // offset 40
	__u8         daddr_v6[16]; // offset 56
};

struct flow_event {
	__u32 pid;
	__u32 uid;
	char  comm[TASK_COMM_LEN];
	__u32 saddr;           // big-endian
	__u32 daddr;           // big-endian
	__u16 sport;
	__u16 dport;
	__u8  direction;       // 0 = outbound (we called connect), 1 = inbound (accept)
	__u8  _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB
} flow_events SEC(".maps");

SEC("tp/sock/inet_sock_set_state")
int trace_flow(struct sock_state_ctx *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)     return 0;
	if (ctx->newstate != TCP_ESTABLISHED) return 0;
	if (ctx->family   != AF_INET)         return 0;

	struct flow_event *e = bpf_ringbuf_reserve(&flow_events, sizeof(*e), 0);
	if (!e) return 0;

	e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	e->uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__builtin_memcpy(&e->saddr, ctx->saddr, 4);
	__builtin_memcpy(&e->daddr, ctx->daddr, 4);
	e->sport = ctx->sport;
	e->dport = ctx->dport;

	// Heuristic: if we're connecting TO a lower-numbered port we're the client.
	e->direction = (ctx->sport > ctx->dport) ? 0 : 1;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
