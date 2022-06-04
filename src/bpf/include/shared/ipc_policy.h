// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_IPC_POLICY_SHARED_H
#define BPFCONTAIN_IPC_POLICY_SHARED_H

#include "vmlinux.h"

#include "defs.h"
#include "policy.h"

/**
 * Policy key for IPC operations */
typedef struct {
	// Policy id for the sender
    u64 policy_id;
	// Policy id for the receiver
    u64 other_policy_id;
} __PACKED ipc_policy_key_t;

/**
 * Policy value for IPC operations */
typedef struct {
	// Policy decision
    policy_decision_t decision;
} __PACKED ipc_policy_val_t;

#endif /* ifndef BPFCONTAIN_IPC_POLICY_SHARED_H */
