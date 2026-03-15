// SPDX-License-Identifier: GPL-2.0
//
// Process execution auditor — hooks syscalls:sys_enter_execve tracepoint.
// No vmlinux.h required; uses stable raw-syscall tracepoint layout.
// Full cmdline is read by the Go layer from /proc/<pid>/cmdline.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN  16
#define MAX_FILENAME  256

// Layout for any sys_enter_* tracepoint on x86-64.
// common header (8 B) | syscall_nr (long = 8 B) | args[6] (unsigned long each).
struct sys_enter_ctx {
	__u64         _common;     // 8 bytes
	long          syscall_nr;  // offset 8
	unsigned long args[6];     // offset 16: args[0]=filename, args[1]=argv, args[2]=envp
};

struct exec_event {
	__u32 pid;
	__u32 uid;
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} exec_events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_exec(struct sys_enter_ctx *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) return 0;

	e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	e->uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// filename is the first syscall argument (userspace pointer)
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
	                        (const char *)ctx->args[0]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
