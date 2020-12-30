// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include "progs.bpf.h"

/* ========================================================================= *
 * BPF Maps                                                                  *
 * ========================================================================= */

/* Active (containerized) processes */
BPF_LRU_HASH(processes, u32, struct bpfcon_process, BPFCON_MAX_PROCESSES, 0);

/* Active inodes associated with containerized processes */
BPF_LRU_HASH(procfs_inodes, u32, struct inode_key, BPFCON_MAX_PROCESSES, 0);

/* Active containers */
BPF_HASH(containers, u64, struct bpfcon_container, BPFCON_MAX_CONTAINERS, 0);

/* Filesystem policy */
BPF_HASH(fs_allow, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(fs_deny, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* File policy */
BPF_HASH(file_allow, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(file_deny, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Device policy */
BPF_HASH(dev_allow, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(dev_deny, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Capability policy */
BPF_HASH(cap_allow, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(cap_deny, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* ========================================================================= *
 * Helpers                                                                   *
 * ========================================================================= */

/* ========================================================================= *
 * Filesystem, File, Device Policy                                           *
 * ========================================================================= */

/* ========================================================================= *
 * Bookkeeping                                                               *
 * ========================================================================= */

/* ========================================================================= *
 * Uprobe Commands                                                           *
 * ========================================================================= */

SEC("uprobe/containerize")
int BPF_KPROBE(containerize, int *ret_p, u64 container_id)
{
    int ret = 0;

    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

out:
    if (ret_p)
        bpf_probe_write_user(ret_p, &ret, sizeof(ret));
    return 0;
}

/* ========================================================================= *
 * License String                                                            *
 * ========================================================================= */

char LICENSE[] SEC("license") = "GPL";
