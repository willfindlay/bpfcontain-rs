// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_AUDIT_SHARED_H
#define BPFCONTAIN_AUDIT_SHARED_H

#include "vmlinux.h"

#include "shared/capability_policy.h"
#include "shared/file_policy.h"
#include "shared/ipc_policy.h"
#include "shared/signal_policy.h"
#include "shared/socket_policy.h"

/**
 * Specifies the audit level, used to control verbosity in userspace. */
typedef enum {
    AUDIT__NONE    = 0,
    AUDIT_ALLOW    = (1U << 0), // Audit policy allows
    AUDIT_DENY     = (1U << 1), // Audit policy denials
    AUDIT_TAINT    = (1U << 2), // Audit policy taints
    AUDIT_INFO     = (1U << 3), // Audit info
    AUDIT_WARN     = (1U << 4), // Audit warnings
    AUDIT__UNKNOWN = (1U << 5),
} audit_level_t;

#define should_audit(level) (level & audit_level)

/**
 * Specifies the inner type container in an audit_data_t. */
typedef enum {
    AUDIT_TYPE_FILE,
    AUDIT_TYPE_CAP,
    AUDIT_TYPE_NET,
    AUDIT_TYPE_IPC,
    AUDIT_TYPE_SIGNAL,
    AUDIT_TYPE__UNKOWN,
} audit_type_t;

/**
 * Audit data representing a generic string. */
typedef struct {
    u8 inner_str[512];
} audit_string_t;

/**
 * Audit data representing a file access. */
typedef struct {
    file_permission_t access;
    u64 st_ino;
    u32 st_dev;
} audit_file_t;

/**
 * Audit data representing a capability access. */
typedef struct {
    capability_t cap;
} audit_cap_t;

/**
 * Audit data representing net access. */
typedef struct {
    net_operation_t operation;
} audit_net_t;

/**
 * Audit data representing ipc access. */
typedef struct {
    u64 other_policy_id; // The other policy ID
    u8 sender;           // 1 if we are the sender, 0 otherwise
} audit_ipc_t;

/**
 * Audit data representing signal access. */
typedef struct {
    u64 other_policy_id;       // The other policy ID
    signal_operation_t signal; // The signal number, encoded as an access vector
} audit_signal_t;

/**
 * Common audit data. */
typedef struct {
    u8 comm[16];
    u64 policy_id;
    u32 pid;
    u32 tgid;
    audit_level_t level;
    audit_type_t type;
    union {
        audit_file_t file;
        audit_cap_t cap;
        audit_net_t net;
        audit_ipc_t ipc;
        audit_signal_t signal;
    };
} audit_data_t;

#endif /* ifndef BPFCONTAIN_AUDIT_SHARED_H */
