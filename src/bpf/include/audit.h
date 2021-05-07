// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef AUDIT_H
#define AUDIT_H

#include "user_types.h"
#include "policy.h"

/* ========================================================================= *
 * Audit Levels                                                              *
 * ========================================================================= */

typedef enum {
    BC_AUDIT_DENY = 0x1,   // Audit denials
    BC_AUDIT_TAINT = 0x2,  // Audit taints
    BC_AUDIT_ALLOW = 0x4,  // Audit allows
} audit_level_t;

#define DEFAULT_AUDIT_LEVEL BC_AUDIT_DENY | BC_AUDIT_TAINT

/* ========================================================================= *
 * Common Audit Types                                                        *
 * ========================================================================= */

typedef struct {
    policy_decision_t decision;
    u64 policy_id;
    u32 pid;
    u32 tgid;
    u8 comm[16];
} audit_common_t;

/* ========================================================================= *
 * Policy-Specific Audit Types                                               *
 * ========================================================================= */

typedef struct {
    audit_common_t common;
    file_permission_t access;
    u64 st_ino;
    u32 st_dev;
    // u8 pathname[PATH_MAX];
} audit_file_t;

typedef struct {
    audit_common_t common;
    capability_t cap;
} audit_cap_t;

typedef struct {
    audit_common_t common;
    net_operation_t operation;
} audit_net_t;

typedef struct {
    audit_common_t common;
    u64 other_policy_id;
    u8 sender;  // 1 if we are the sender, 0 otherwise
} audit_ipc_t;

#endif /* ifndef AUDIT_H */
