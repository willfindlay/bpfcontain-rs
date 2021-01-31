// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

/* This file contains struct definitions for map keys and values, used both by
 * the BPF program, libbpfcontain, and bpfcontain-rs. These definitions must be
 * kept in sync with their Rust binding counterparts in src/libbpfcontain.rs */

#ifndef STRUCTS_H
#define STRUCTS_H

#ifndef __VMLINUX_H__
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
#endif

#define TASK_COMM_LEN 16
#define PATH_MAX      4096

/* ========================================================================= *
 * Enum Types for Writing Policy                                             *
 * ========================================================================= */

// clang-format off

/* Possible policy decisions */
typedef enum {
    BPFCON_NO_DECISION = 0x00,
    BPFCON_ALLOW       = 0x01,
    BPFCON_DENY        = 0x02,
    BPFCON_TAINT       = 0x04,
} policy_decision_t;

/* Permissions, partly based on AppArmor */
typedef enum {
    BPFCON_MAY_EXEC      = 0x00000001,
    BPFCON_MAY_WRITE     = 0x00000002,
    BPFCON_MAY_READ      = 0x00000004,
    BPFCON_MAY_APPEND    = 0x00000008,
    BPFCON_MAY_CREATE    = 0x00000010,
    BPFCON_MAY_DELETE    = 0x00000020,
    BPFCON_MAY_RENAME    = 0x00000040,
    BPFCON_MAY_SETATTR   = 0x00000080,
    BPFCON_MAY_CHMOD     = 0x00000100,
    BPFCON_MAY_CHOWN     = 0x00000200,
    BPFCON_MAY_LINK      = 0x00000400,
    BPFCON_MAY_EXEC_MMAP = 0x00000800,
    BPFCON_MAY_CHDIR     = 0x00001000,
} file_permission_t;

/* Tunable capabilities
 * Note: Fow now, we only support these capabilities. Most of the other
 * capabilities don't really make sense in the context of a container, but may
 * be required later for compatibility with other container implementations.
 */
typedef enum {
    BPFCON_CAP_CHOWN              = 0x0000000000000001,
    BPFCON_CAP_DAC_OVERRIDE       = 0x0000000000000002,
    BPFCON_CAP_DAC_READ_SEARCH    = 0x0000000000000004,
    BPFCON_CAP_FOWNER             = 0x0000000000000008,
    BPFCON_CAP_FSETID             = 0x0000000000000010,
    BPFCON_CAP_KILL               = 0x0000000000000020,
    BPFCON_CAP_SETGID             = 0x0000000000000040,
    BPFCON_CAP_SETUID             = 0x0000000000000080,
    BPFCON_CAP_SETPCAP            = 0x0000000000000100,
    BPFCON_CAP_LINUX_IMMUTABLE    = 0x0000000000000200,
    BPFCON_CAP_NET_BIND_SERVICE   = 0x0000000000000400,
    BPFCON_CAP_NET_BROADCAST      = 0x0000000000000800,
    BPFCON_CAP_NET_ADMIN          = 0x0000000000001000,
    BPFCON_CAP_NET_RAW            = 0x0000000000002000,
    BPFCON_CAP_IPC_LOCK           = 0x0000000000004000,
    BPFCON_CAP_IPC_OWNER          = 0x0000000000008000,
    BPFCON_CAP_SYS_MODULE         = 0x0000000000010000,
    BPFCON_CAP_SYS_RAWIO          = 0x0000000000020000,
    BPFCON_CAP_SYS_CHROOT         = 0x0000000000040000,
    BPFCON_CAP_SYS_PTRACE         = 0x0000000000080000,
    BPFCON_CAP_SYS_PACCT          = 0x0000000000100000,
    BPFCON_CAP_SYS_ADMIN          = 0x0000000000200000,
    BPFCON_CAP_SYS_BOOT           = 0x0000000000400000,
    BPFCON_CAP_SYS_NICE           = 0x0000000000800000,
    BPFCON_CAP_SYS_RESOURCE       = 0x0000000001000000,
    BPFCON_CAP_SYS_TIME           = 0x0000000002000000,
    BPFCON_CAP_SYS_TTY_CONFIG     = 0x0000000004000000,
    BPFCON_CAP_MKNOD              = 0x0000000008000000,
    BPFCON_CAP_LEASE              = 0x0000000010000000,
    BPFCON_CAP_AUDIT_WRITE        = 0x0000000020000000,
    BPFCON_CAP_AUDIT_CONTROL      = 0x0000000040000000,
    BPFCON_CAP_SETFCAP            = 0x0000000080000000,
    BPFCON_CAP_MAC_OVERRIDE       = 0x0000000100000000,
    BPFCON_CAP_MAC_ADMIN          = 0x0000000200000000,
    BPFCON_CAP_SYSLOG             = 0x0000000400000000,
    BPFCON_CAP_WAKE_ALARM         = 0x0000000800000000,
    BPFCON_CAP_BLOCK_SUSPEND      = 0x0000001000000000,
    BPFCON_CAP_AUDIT_READ         = 0x0000002000000000,
    BPFCON_CAP_PERFMON            = 0x0000004000000000,
    BPFCON_CAP_BPF                = 0x0000008000000000,
    BPFCON_CAP_CHECKPOINT_RESTORE = 0x0000010000000000,
} capability_t;

/* Network categories */
typedef enum {
    BPFCON_NET_WWW = 0x01,
    BPFCON_NET_IPC = 0x02,
} net_category_t;

/* Network operations */
typedef enum {
    BPFCON_NET_CONNECT  = 0x00000001,
    BPFCON_NET_BIND     = 0x00000002,
    BPFCON_NET_ACCEPT   = 0x00000004,
    BPFCON_NET_LISTEN   = 0x00000008,
    BPFCON_NET_SEND     = 0x00000010,
    BPFCON_NET_RECV     = 0x00000020,
    BPFCON_NET_CREATE   = 0x00000040,
    BPFCON_NET_SHUTDOWN = 0x00000080,
} net_operation_t;

// clang-format on

#define TASK_INODE_PERM_MASK                                     \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND |    \
     BPFCON_MAY_CREATE | BPFCON_MAY_DELETE | BPFCON_MAY_RENAME | \
     BPFCON_MAY_SETATTR | BPFCON_MAY_CHOWN | BPFCON_MAY_CHMOD |  \
     BPFCON_MAY_LINK | BPFCON_MAY_CHDIR)

#define PROC_INODE_PERM_MASK \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND | BPFCON_MAY_CHDIR)

#define OVERLAYFS_PERM_MASK                                       \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND |     \
     BPFCON_MAY_EXEC | BPFCON_MAY_EXEC_MMAP BPFCON_MAY_CREATE |   \
     BPFCON_MAY_DELETE | BPFCON_MAY_RENAME | BPFCON_MAY_SETATTR | \
     BPFCON_MAY_CHOWN | BPFCON_MAY_CHMOD | BPFCON_MAY_LINK | BPFCON_MAY_CHDIR)

/* ========================================================================= *
 * Per-Event Logging                                                         *
 * ========================================================================= */

typedef enum {
    BC_AUDIT_DENY = 0x1,   // Audit denials
    BC_AUDIT_TAINT = 0x2,  // Audit taints
    BC_AUDIT_ALLOW = 0x4,  // Audit allows
} audit_level_t;

#define DEFAULT_AUDIT_LEVEL BC_AUDIT_DENY | BC_AUDIT_TAINT

typedef struct {
    policy_decision_t decision;
    u64 policy_id;
    u32 pid;
    u32 tgid;
    u8 comm[16];
} audit_common_t;

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

/* ========================================================================= *
 * Process and Container State                                               *
 * ========================================================================= */

// TODO: use this wherever we have a policy id or a container id
typedef u64 policy_id_t;
typedef u64 container_id_t;

typedef struct {
    container_id_t container_id;
    u32 host_pid;
    u32 host_tgid;
    u32 pid;
    u32 tgid;
} process_t;

// Represents the state of a container
typedef struct {
    // id of bpfcontain policy associated with this container
    policy_id_t policy_id;
    // bpfcontain's version of a container id,
    // also used as a key into the map of containers
    container_id_t container_id;
    // the mount namespace id of this container
    u32 mnt_ns_id;
    // the pid namespace id of this container
    u32 pid_ns_id;
    // reference count of the container (how many tasks are running inside it)
    // this should only be incremented and decremented atomically
    u32 refcount;
    // Is the container in a tainted state?
    u8 tainted : 1;
    u8 default_deny : 1;
    // often corresponds with container id on the docker side
    char uts_name[16];
} container_t;

/* ========================================================================= *
 * Keys for BPF Maps                                                         *
 * ========================================================================= */

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
    u64 policy_id;
} __attribute__((__packed__)) cap_policy_key_t;

typedef struct {
    u64 policy_id;
} __attribute__((__packed__)) net_policy_key_t;

typedef struct {
    u64 policy_id;
    u64 other_policy_id;
} __attribute__((__packed__)) ipc_policy_key_t;

typedef struct {
    u64 inode_id;
    u32 device_id;
} __attribute__((__packed__)) inode_key_t;

#endif /* STRUCTS_H */
