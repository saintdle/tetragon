// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct hostpid_filter {
	__s32 fd;
	__s32 whence;
	__s64 off;
};

struct hostpid_event {
	__s32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct hostpid_filter);
	__uint(max_entries, 1);
} tg_hpid_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, struct hostpid_event);
	__uint(max_entries, 128);
} tg_hpid_event_map SEC(".maps");

/* helper program to retrieve tetragon's host pid via an lseek bogus call */
__attribute__((section(("kprobe/lseek_hook")), used)) int
tg_hpid_hook(struct pt_regs *ctx)
{
	int zero = 0;
	struct hostpid_event ev;
	struct hostpid_filter *f;
	struct pt_regs *ctx_;

	f = map_lookup_elem(&tg_hpid_filter_map, &zero);
	if (!f)
		return 0;

	ctx_ = PT_REGS_SYSCALL_REGS(ctx);
	if (PT_REGS_PARM1_CORE_SYSCALL(ctx_) != f->fd)
		return 0;

	if (PT_REGS_PARM2_CORE_SYSCALL(ctx_) != f->off)
		return 0;

	if (PT_REGS_PARM3_CORE_SYSCALL(ctx_) != f->whence)
		return 0;

	ev.pid = get_current_pid_tgid() >> 32;
	perf_event_output(ctx, &tg_hpid_event_map, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}
