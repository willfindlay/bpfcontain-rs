// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#ifndef PROGS_BPF_H
#define PROGS_BPF_H

// This must be first
#include "vmlinux.h"

// These must be below vmlinux.h
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

#include "kernel_defs.h"
#include "maps.h"

#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))

#ifndef BPFCON_MAX_CONTAINERS
#define BPFCON_MAX_CONTAINERS 10240
#endif

#ifndef BPFCON_MAX_PROCESSES
#define BPFCON_MAX_PROCESSES 10240
#endif

#ifndef BPFCON_MAX_POLICY
#define BPFCON_MAX_POLICY 10240
#endif

#define BPFCON_NO_DECISION 0x00
#define BPFCON_ALLOW       0x01
#define BPFCON_DENY        0x02

/* Permissions, partly based on AppArmor */
#define BPFCON_MAY_EXEC      MAY_EXEC
#define BPFCON_MAY_WRITE     MAY_WRITE
#define BPFCON_MAY_READ      MAY_READ
#define BPFCON_MAY_APPEND    MAY_APPEND
#define BPFCON_MAY_CREATE    0x00000010
#define BPFCON_MAY_DELETE    0x00000020
#define BPFCON_MAY_RENAME    0x00000040
#define BPFCON_MAY_SETATTR   0x00000080
#define BPFCON_MAY_CHMOD     0x00000100
#define BPFCON_MAY_CHOWN     0x00000200
#define BPFCON_MAY_LINK      0x00000400
#define BPFCON_MAY_EXEC_MMAP 0x00000800
#define BPFCON_MAY_CHDIR     0x00001000

/* Tunable capabilities */
#define BPFCON_NET_BIND      0x00000001
#define BPFCON_NET_RAW       0x00000002
#define BPFCON_NET_BROADCAST 0x00000004
#define BPFCON_DAC_OVERRIDE  0x00000008

struct bpfcon_container {
    u8 default_deny;
};

struct bpfcon_process {
    u64 container_id;
    u32 pid;
    u32 tgid;
    u8 in_execve;
};

struct fs_policy_key {
    u64 container_id;
    u32 device_id;
};

struct file_policy_key {
    u64 container_id;
    u64 inode_id;
    u32 device_id;
};

struct dev_policy_key {
    u64 container_id;
    u32 major;
};

struct cap_policy_key {
    u64 container_id;
};

struct inode_key {
    u64 inode_id;
    u32 device_id;
};

static __always_inline struct bpfcon_process *add_process(u32 pid, u32 tgid,
                                                          u64 policy_key);

static __always_inline int do_fs_permission_file(u64, struct file *, u32);
static __always_inline int do_fs_permission_inode(u64, struct inode *, u32);

#endif /* ifndef PROGS_BPF_H */

