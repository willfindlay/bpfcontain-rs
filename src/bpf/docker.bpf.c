// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#include "bpf.h"
#include "config.h"
#include "kernel_defs.h"
#include "log.h"
#include "docker.h"
#include "map_defs.h"

#define IOCTL_POPULATE_OVERLAYFS_MAGIC 0xBEEFDEAD

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(populate_overlayfs, struct file *file, unsigned int cmd, unsigned long arg) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid != bpfcontain_pid) {
        return 0;
    }

    if (cmd != IOCTL_POPULATE_OVERLAYFS_MAGIC) {
        return 0;
    }

	add_inode_to_overlayfs(arg, BPF_CORE_READ(file, f_inode));

    return 0;
}

/* SEC("kprobe/ovl_copy_xattr") */
/* int BPF_KPROBE(ovl_copy_xattr, struct super_block *sb, struct dentry *old, struct dentry *new) { */
/* 	u64 old_inum = BPF_CORE_READ(old, d_inode, i_ino); */
/* 	u32 old_dev = new_encode_dev(BPF_CORE_READ(old, d_inode, i_sb, s_dev)); */

/* 	u64 new_inum = BPF_CORE_READ(new, d_inode, i_ino); */
/* 	u32 new_dev = new_encode_dev(BPF_CORE_READ(new, d_inode, i_sb, s_dev)); */

/* 	u32 sb_dev = new_encode_dev(BPF_CORE_READ(sb, s_dev)); */

/* 	LOG(LOG_DEBUG, "copying up xattr old=(%llu,%u) new=(%llu,%u) sb=%u", old_inum, old_dev, new_inum, new_dev, sb_dev); */

/* 	return 0; */
/* } */

static __always_inline struct ovl_inode* OVL_I(struct inode *inode) {
	return container_of(inode, struct ovl_inode, vfs_inode);
}

SEC("kprobe/ovl_encode_real_fh")
int BPF_KPROBE(do_overlayfs, struct ovl_fs *ofs, struct dentry *real, bool is_upper) {
	u64 real_inum = BPF_CORE_READ(real, d_inode, i_ino);
	u32 real_dev = new_encode_dev(BPF_CORE_READ(real, d_inode, i_sb, s_dev));

	LOG(LOG_DEBUG, "ovl_encode_real_fh real=(%llu,%u) is_upper=%d", real_inum, real_dev, is_upper);
	return 0;
}


SEC("kprobe/ovl_inode_init")
int BPF_KPROBE(ovl_inode_init, struct inode *inode, struct ovl_inode_params *oip, unsigned long ino, int fsid) {
	u32 pid = bpf_get_current_pid_tgid();

    process_t *process = bpf_map_lookup_elem(&processes, &pid);
    if (!process)
        return 0;

    container_t *container = bpf_map_lookup_elem(&containers, &process->container_id);
	if (!container)
		return 0;

	LOG(LOG_DEBUG, "ovl_inode_init ino=%lu fsid=%d", ino, fsid);

	char mount[64];
	bpf_probe_read_kernel_str((char *)mount, 64, BPF_CORE_READ(oip, lowerpath, dentry, d_inode, i_sb, s_root, d_name.name));
	//bpf_probe_read_kernel_str((char *)mount, 64, BPF_CORE_READ(oip, lowerpath, dentry, d_name.name));
	LOG(LOG_DEBUG, "ovl mount %s", mount);

	// FIXME: this is just temporary, for testing
	file_policy_key_t key = {};
	key.policy_id = container->policy_id;
	key.inode_id = ino;
	if (!fsid) {
		fsid = root_fs_id;
	}
	key.device_id = fsid;

	file_policy_val_t val = {};
	val.allow = OVERLAYFS_PERM_MASK | BPFCON_MAY_IOCTL;

	bpf_map_update_elem(&file_policy, &key, &val, BPF_NOEXIST);

	return 0;
}
