// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __BPF_LOCAL_TYPES_H__
#define __BPF_LOCAL_TYPES_H__

struct inode_info_type {
	/* Mark that we did read data and initialized this
	 * since i_nlink can be zero anyway.
	 */
	__u32 initialized;
	__u32 i_nlink;
};

#endif
