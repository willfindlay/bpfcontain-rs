// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include "bpf.h"
#include "config.h"

#define IOCTL_POPULATE_ROOTFS_MAGIC 0xDEADBEEF

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(populate_rootfs, struct file *file, unsigned int cmd, unsigned long arg) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid != bpfcontain_pid) {
        return 0;
    }

    if (cmd != IOCTL_POPULATE_ROOTFS_MAGIC || arg != IOCTL_POPULATE_ROOTFS_MAGIC) {
        return 0;
    }

    root_fs_id = BPF_CORE_READ(file, f_inode, i_sb, s_bdi, id);

    return 0;
}
