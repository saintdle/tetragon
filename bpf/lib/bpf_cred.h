// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __BPF_CRED_
#define __BPF_CRED_

/*
 * TODO: we have tg_cred that is defined in bpf/process/cred.h
 * that includes the full credentials definition and is used in
 * kprobes. However since we are also moving to use creds for
 * exec events, so let's do it step by step, as we already
 * have the capabilities there inside the execve_map and the
 * user space cache, so we start with this minimal credential
 * object that holds only uids/gids, then we follow up by
 * moving the capabilities into it, and make this cred the
 * new storage in execve_map and user space process cache.
 */
struct tg_cred_minimal {
	__u32 uid;
	__u32 gid;
	__u32 suid;
	__u32 sgid;
	__u32 euid;
	__u32 egid;
	__u32 fsuid;
	__u32 fsgid;
	__u32 securebits;
	__u32 pad;
} __attribute__((packed));

#endif
