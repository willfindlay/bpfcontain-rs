// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef POLICY_H
#define POLICY_H

#include "user_types.h"

/* ========================================================================= *
 * Common Policy Structs                                                     *
 * ========================================================================= */

/* Possible policy decisions */
typedef enum {
    BPFCON_NO_DECISION = 0x00,
    BPFCON_ALLOW = 0x01,
    BPFCON_DENY = 0x02,
    BPFCON_TAINT = 0x04,
} policy_decision_t;

typedef struct {
    u8 default_taint : 1;
} __attribute__((__packed__)) policy_common_t;

/* ========================================================================= *
 * File Policy                                                               *
 * ========================================================================= */

/* Permissions, partly based on AppArmor */
typedef enum {
    BPFCON_MAY_EXEC = 0x01,
    BPFCON_MAY_WRITE = 0x02,
    BPFCON_MAY_READ = 0x04,
    BPFCON_MAY_APPEND = 0x08,
    BPFCON_MAY_CHMOD = 0x10,
    BPFCON_MAY_DELETE = 0x20,
    BPFCON_MAY_EXEC_MMAP = 0x40,
    BPFCON_MAY_LINK = 0x80,
} file_permission_t;

#define BPFCON_ALL_FS_PERM_MASK                                 \
    (BPFCON_MAY_EXEC | BPFCON_MAY_WRITE | BPFCON_MAY_READ |     \
     BPFCON_MAY_APPEND | BPFCON_MAY_CHMOD | BPFCON_MAY_DELETE | \
     BPFCON_MAY_EXEC_MMAP)

#define TASK_INODE_PERM_MASK                                  \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND | \
     BPFCON_MAY_DELETE | BPFCON_MAY_CHMOD)

#define PROC_INODE_PERM_MASK \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND)

#define OVERLAYFS_PERM_MASK BPFCON_ALL_FS_PERM_MASK

typedef struct {
    u64 policy_id;
    u32 device_id;
} __attribute__((__packed__)) fs_policy_key_t;

typedef struct {
    u64 policy_id;
    u64 inode_id;
    u32 device_id;
} __attribute__((__packed__)) file_policy_key_t;

static const s64 MINOR_WILDCARD = -1;
typedef struct {
    u64 policy_id;
    u32 major;
    s64 minor;
} __attribute__((__packed__)) dev_policy_key_t;

typedef struct {
    file_permission_t allow;
    file_permission_t taint;
    file_permission_t deny;
} __attribute__((__packed__)) file_policy_val_t;

typedef struct {
    u64 inode_id;
    u32 device_id;
} __attribute__((__packed__)) inode_key_t;

/* ========================================================================= *
 * Capabilitity Policy                                                       *
 * ========================================================================= */

/* Tunable capabilities */
typedef enum {
    BPFCON_CAP_CHOWN = 0x0000000000000001,
    BPFCON_CAP_DAC_OVERRIDE = 0x0000000000000002,
    BPFCON_CAP_DAC_READ_SEARCH = 0x0000000000000004,
    BPFCON_CAP_FOWNER = 0x0000000000000008,
    BPFCON_CAP_FSETID = 0x0000000000000010,
    BPFCON_CAP_KILL = 0x0000000000000020,
    BPFCON_CAP_SETGID = 0x0000000000000040,
    BPFCON_CAP_SETUID = 0x0000000000000080,
    BPFCON_CAP_SETPCAP = 0x0000000000000100,
    BPFCON_CAP_LINUX_IMMUTABLE = 0x0000000000000200,
    BPFCON_CAP_NET_BIND_SERVICE = 0x0000000000000400,
    BPFCON_CAP_NET_BROADCAST = 0x0000000000000800,
    BPFCON_CAP_NET_ADMIN = 0x0000000000001000,
    BPFCON_CAP_NET_RAW = 0x0000000000002000,
    BPFCON_CAP_IPC_LOCK = 0x0000000000004000,
    BPFCON_CAP_IPC_OWNER = 0x0000000000008000,
    BPFCON_CAP_SYS_MODULE = 0x0000000000010000,
    BPFCON_CAP_SYS_RAWIO = 0x0000000000020000,
    BPFCON_CAP_SYS_CHROOT = 0x0000000000040000,
    BPFCON_CAP_SYS_PTRACE = 0x0000000000080000,
    BPFCON_CAP_SYS_PACCT = 0x0000000000100000,
    BPFCON_CAP_SYS_ADMIN = 0x0000000000200000,
    BPFCON_CAP_SYS_BOOT = 0x0000000000400000,
    BPFCON_CAP_SYS_NICE = 0x0000000000800000,
    BPFCON_CAP_SYS_RESOURCE = 0x0000000001000000,
    BPFCON_CAP_SYS_TIME = 0x0000000002000000,
    BPFCON_CAP_SYS_TTY_CONFIG = 0x0000000004000000,
    BPFCON_CAP_MKNOD = 0x0000000008000000,
    BPFCON_CAP_LEASE = 0x0000000010000000,
    BPFCON_CAP_AUDIT_WRITE = 0x0000000020000000,
    BPFCON_CAP_AUDIT_CONTROL = 0x0000000040000000,
    BPFCON_CAP_SETFCAP = 0x0000000080000000,
    BPFCON_CAP_MAC_OVERRIDE = 0x0000000100000000,
    BPFCON_CAP_MAC_ADMIN = 0x0000000200000000,
    BPFCON_CAP_SYSLOG = 0x0000000400000000,
    BPFCON_CAP_WAKE_ALARM = 0x0000000800000000,
    BPFCON_CAP_BLOCK_SUSPEND = 0x0000001000000000,
    BPFCON_CAP_AUDIT_READ = 0x0000002000000000,
    BPFCON_CAP_PERFMON = 0x0000004000000000,
    BPFCON_CAP_BPF = 0x0000008000000000,
    BPFCON_CAP_CHECKPOINT_RESTORE = 0x0000010000000000,
} capability_t;

typedef struct {
    u64 policy_id;
} __attribute__((__packed__)) cap_policy_key_t;

typedef struct {
    capability_t allow;
    capability_t taint;
    capability_t deny;
} __attribute__((__packed__)) cap_policy_val_t;

/* ========================================================================= *
 * Network Policy                                                            *
 * ========================================================================= */

/* Network categories */
typedef enum {
    BPFCON_NET_WWW = 0x01,
    BPFCON_NET_IPC = 0x02,
} net_category_t;

/* Network operations */
typedef enum {
    BPFCON_NET_CONNECT = 0x01,
    BPFCON_NET_BIND = 0x02,
    BPFCON_NET_ACCEPT = 0x04,
    BPFCON_NET_LISTEN = 0x08,
    BPFCON_NET_SEND = 0x10,
    BPFCON_NET_RECV = 0x20,
    BPFCON_NET_CREATE = 0x40,
    BPFCON_NET_SHUTDOWN = 0x80,
} net_operation_t;

typedef struct {
    u64 policy_id;
} __attribute__((__packed__)) net_policy_key_t;

typedef struct {
    net_operation_t allow;
    net_operation_t taint;
    net_operation_t deny;
} __attribute__((__packed__)) net_policy_val_t;

/* ========================================================================= *
 * IPC Policy                                                                *
 * ========================================================================= */

typedef struct {
    u64 policy_id;
    u64 other_policy_id;
} __attribute__((__packed__)) ipc_policy_key_t;

typedef struct {
    policy_decision_t decision;
} __attribute__((__packed__)) ipc_policy_val_t;

#endif /* ifndef POLICY_H */
