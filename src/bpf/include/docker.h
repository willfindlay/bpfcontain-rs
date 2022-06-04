#ifndef BPFCONTAIN_DOCKER_H
#define BPFCONTAIN_DOCKER_H

#include "bpf.h"
#include "maps.h"
#include "kernel_defs.h"

typedef struct {
	u64 inum;
	u32 device;
	u64 overlayfs_id;
} OverlayfsKey;

BPF_HASH(overlayfs_inodes, OverlayfsKey, u8, 1024000, 0, 0) __weak;

static __always_inline int add_inode_to_overlayfs(u64 overlayfs_id, struct inode *inode) {
	if (!inode) {
		return 0;
	}

	u8 one = 1;

	OverlayfsKey key = {};
	key.overlayfs_id = overlayfs_id;
	key.inum = BPF_CORE_READ(inode, i_ino);
	key.device = new_encode_dev(BPF_CORE_READ(inode, i_sb, s_dev));

	bpf_map_update_elem(&overlayfs_inodes, &key, &one, BPF_NOEXIST);

	return 0;
}

#endif /* ifndef BPFCONTAIN_DOCKER_H */
