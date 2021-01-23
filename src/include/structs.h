// SPDX-License-Identifier: GPL-2
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
    BPFCON_CAP_NET_BIND_SERVICE = 0x00000001,
    BPFCON_CAP_NET_RAW          = 0x00000002,
    BPFCON_CAP_NET_BROADCAST    = 0x00000004,
    BPFCON_CAP_DAC_OVERRIDE     = 0x00000008,
    BPFCON_CAP_DAC_READ_SEARCH  = 0x00000010,
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
    EA_UNKNOWN = 0,
    EA_ERROR,
    EA_DENY,
    EA_IMPLICIT_DENY,
    EA_TAINT,
} event_action_t;

typedef enum {
    ET_NONE = 0,
    ET_FILE,
    ET_CAP,
    ET_NET,
    ET_IPC,
    ET_NO_SUCH_CONTAINER,
} event_type_t;

typedef struct file_info {
    u64 inode_id;
    u32 device_id;
    file_permission_t access;
} file_info_t;

typedef struct cap_info {
    capability_t cap;
} cap_info_t;

typedef struct net_info {
    net_operation_t operation;
} net_info_t;

typedef struct ipc_info {
    u32 sender_pid;
    u32 receiver_pid;
    u64 sender_id;
    u64 receiver_id;
} ipc_info_t;

typedef struct bpfcon_event_info {
    event_type_t type;
    union {
        file_info_t file_info;
        cap_info_t cap_info;
        net_info_t net_info;
        ipc_info_t ipc_info;
    } info;
} event_info_t;

typedef struct event {
    event_action_t action;
    u64 policy_id;
    u32 pid;
    u32 tgid;
    u8 comm[16];
    event_info_t info;
} event_t;

/* ========================================================================= *
 * Process and Container State                                               *
 * ========================================================================= */

typedef struct policy {
    u8 default_deny;
    u8 default_taint;
} policy_t;

typedef struct bpfcon_process {
    u64 policy_id;
    u32 pid;
    u32 tgid;
    u8 in_execve : 1;
    u8 tainted : 1;
} process_t;

// Represents the state of a container
typedef struct bpfcon_container {
    u64 policy_id;     // bpfcontain policy associated with this container
    u64 container_id;  // bpfcontain's version of a container id, also used as a
                       // key into the map of containers
    u32 mnt_ns_id;     // the mount namespace id of this container
    u32 pid_ns_id;     // the pid namespace id of this container
    u8 uts_name[16];   // often corresponds with container id on the docker side
} container_t;

/* ========================================================================= *
 * Keys for BPF Maps                                                         *
 * ========================================================================= */

typedef struct fs_policy_key {
    u64 policy_id;
    u32 device_id;
} __attribute__((__packed__)) fs_policy_key_t;

typedef struct file_policy_key {
    u64 policy_id;
    u64 inode_id;
    u32 device_id;
} __attribute__((__packed__)) file_policy_key_t;

#define MINOR_WILDCARD (~0U)
typedef struct dev_policy_key {
    u64 policy_id;
    u32 major;
    u32 minor;
} __attribute__((__packed__)) dev_policy_key_t;

typedef struct cap_policy_key {
    u64 policy_id;
} __attribute__((__packed__)) cap_policy_key_t;

typedef struct net_policy_key {
    u64 policy_id;
} __attribute__((__packed__)) net_policy_key_t;

typedef struct ipc_policy_key {
    u64 policy_id;
    u64 other_policy_id;
} __attribute__((__packed__)) ipc_policy_key_t;

typedef struct inode_key {
    u64 inode_id;
    u32 device_id;
} __attribute__((__packed__)) inode_key_t;

#endif /* STRUCTS_H */
