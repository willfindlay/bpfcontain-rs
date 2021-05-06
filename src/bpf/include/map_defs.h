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
#include "structs.h"

/* Ring buffer for passing logging events to userspace */
BPF_RINGBUF(audit_file_buf, 4, LIBBPF_PIN_BY_NAME);
BPF_RINGBUF(audit_cap_buf, 4, LIBBPF_PIN_BY_NAME);
BPF_RINGBUF(audit_net_buf, 4, LIBBPF_PIN_BY_NAME);
BPF_RINGBUF(audit_ipc_buf, 4, LIBBPF_PIN_BY_NAME);

/* Active (containerized) processes */
BPF_HASH(processes, u32, process_t, BPFCON_MAX_PROCESSES, LIBBPF_PIN_BY_NAME,
         0);
BPF_HASH(containers, container_id_t, container_t, BPFCON_MAX_CONTAINERS,
         LIBBPF_PIN_BY_NAME, 0);

/* Files and directories which have been created by a containerized process */
BPF_INODE_STORAGE(task_inodes, container_id_t, LIBBPF_PIN_BY_NAME, 0);

/* Common policy */
BPF_HASH(policy_common, policy_id_t, policy_common_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

/* Filesystem policy */
BPF_HASH(fs_policy, fs_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

/* File policy */
BPF_HASH(file_policy, file_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

/* Device policy */
BPF_HASH(dev_policy, dev_policy_key_t, file_policy_val_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

/* Capability policy */
BPF_HASH(cap_policy, cap_policy_key_t, cap_policy_val_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

/* Network policy */
BPF_HASH(net_policy, net_policy_key_t, net_policy_val_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

/* IPC policy */
BPF_HASH(ipc_policy, ipc_policy_key_t, ipc_policy_val_t, BPFCON_MAX_POLICY,
         LIBBPF_PIN_BY_NAME, 0);

#endif /* ifndef MAP_DEFS_H */
