// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef MAP_DEFS_H
#define MAP_DEFS_H

#include "defs.h"
#include "maps.h"
#include "shared/ioctl.h"
#include "shared/process.h"
#include "shared/container.h"
#include "shared/policy.h"
#include "shared/file_policy.h"
#include "shared/capability_policy.h"
#include "shared/signal_policy.h"
#include "shared/ipc_policy.h"
#include "shared/socket_policy.h"

/* Ring buffer for passing logging events to userspace */
BPF_RINGBUF(__audit_buf, 16, 0) __weak;

BPF_PERCPU_ARRAY(ioctl_heap, bpfcontain_ioctl_t, 1, 0, 0) __weak;

/* Active (containerized) processes */
BPF_HASH(processes, u32, process_t, BPFCON_MAX_PROCESSES, 0, 0) __weak;
BPF_HASH(containers, container_id_t, container_t, BPFCON_MAX_CONTAINERS, 0, 0) __weak;

/* Files and directories which have been created by a containerized process */
BPF_INODE_STORAGE(task_inodes, container_id_t, 0, 0) __weak;
// TODO IPC storage when this comes out
/* Maps sysv ipc ids to container ids */
BPF_HASH(ipc_handles, int, u64, BPFCON_MAX_PROCESSES, 0, 0) __weak;

/* Common policy */
BPF_HASH(policy_common, policy_id_t, policy_common_t, BPFCON_MAX_POLICY, 0, 0) __weak;

/* Filesystem policy */
BPF_HASH(fs_policy, fs_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY, 0,
         0) __weak;

/* implicit filesystem policy */
BPF_HASH(fs_implicit_policy, fs_implicit_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY, 0, 0) __weak;

/* File policy */
BPF_HASH(file_policy, file_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY,
         0, 0) __weak;

/* Device policy */
BPF_HASH(dev_policy, dev_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY, 0,
         0) __weak;

/* Capability policy */
BPF_HASH(cap_policy, cap_policy_key_t, cap_policy_val_t, BPFCON_MAX_POLICY, 0,
         0) __weak;

/* Network policy */
BPF_HASH(net_policy, net_policy_key_t, net_policy_val_t, BPFCON_MAX_POLICY, 0,
         0) __weak;

/* IPC policy */
BPF_HASH(ipc_policy, ipc_policy_key_t, ipc_policy_val_t, BPFCON_MAX_POLICY, 0,
         0) __weak;

/* Signal policy */
BPF_HASH(signal_policy, signal_policy_key_t, signal_policy_val_t,
         BPFCON_MAX_POLICY, 0, 0) __weak;

#endif /* ifndef MAP_DEFS_H */
