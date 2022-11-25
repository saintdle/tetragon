// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "bpf_events.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/security_bprm_check"), used)) int
BPF_KPROBE(tg_kp_bprm_check, struct linux_binprm *bprm, int ret)
{
	__u64 tid;
	__u32 pid, zero = 0;
	unsigned int links;
	struct execve_map_value *curr;
	struct execve_heap *heap;
	struct file *file;

	tid = get_current_pid_tgid();
	pid = (tid >> 32);

	curr = execve_map_get(pid);
	if (!curr)
		return 0;

	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return 0;

	memset(&heap->info, 0, sizeof(struct msg_info));

	probe_read(&file, sizeof(file), _(&bprm->file));
	links = BPF_CORE_READ(file, f_inode, __i_nlink);

	heap->info.inode.i_nlink = links;
	heap->info.inode.initialized = 1;
	execve_joined_info_map_set(tid, &heap->info);

	return 0;
}
