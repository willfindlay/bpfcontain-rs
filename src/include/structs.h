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
} PolicyDecision;

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
} FilePermission;

/* Tunable capabilities */
typedef enum {
    BPFCON_CAP_NET_BIND_SERVICE = 0x00000001,
    BPFCON_CAP_NET_RAW          = 0x00000002,
    BPFCON_CAP_NET_BROADCAST    = 0x00000004,
    BPFCON_CAP_DAC_OVERRIDE     = 0x00000008,
    BPFCON_CAP_DAC_READ_SEARCH  = 0x00000010,
} Capability;
// Note: Fow now, we only support these capabilities. Most of the other
// capabilities don't really make sense in the context of a container, but may
// be required later for compatibility with other container implementations.

/* Network categories */
typedef enum {
    BPFCON_NET_WWW = 0x01,
    BPFCON_NET_IPC = 0x02,
} NetCategory;

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
} NetOperation;

// clang-format on

/* ========================================================================= *
 * Per-Event Logging                                                         *
 * ========================================================================= */

typedef enum {
    EV_NO_SUCH_CONTAINER,
    EV_DENY,
    EV_IMPLICIT_DENY,
    EV_TAINT,
} EventCategory;

typedef enum {
    OBJ_NONE,
    OBJ_FILE,
    OBJ_CAP,
    OBJ_NET,
    OBJ_IPC,
} ObjectType;

typedef struct file_info {
    unsigned long inode_id;
    unsigned int device_id;
} FileInfo;

typedef struct cap_info {
    Capability cap;
} CapInfo;

typedef struct net_info {
    NetOperation operation;
} NetInfo;

typedef struct ipc_info {
    unsigned long sender_id;
    unsigned long receiver_id;
} IPCInfo;

typedef struct event {
    EventCategory category;
    ObjectType object_type;
    unsigned long container_id;
    unsigned int pid;
    unsigned int tgid;
    char comm[16];
    union {
        FileInfo file_info;
        CapInfo cap_info;
        NetInfo net_info;
        IPCInfo ipc_info;
    };
} Event;

/* ========================================================================= *
 * Process and Container State                                               *
 * ========================================================================= */

typedef struct bpfcon_container {
    unsigned char default_deny;
    unsigned char default_taint;
} Container;

typedef struct bpfcon_process {
    unsigned long container_id;
    unsigned int pid;
    unsigned int tgid;
    unsigned char in_execve : 1;
    unsigned char tainted : 1;
} Process;

/* ========================================================================= *
 * Keys for BPF Maps                                                         *
 * ========================================================================= */

typedef struct fs_policy_key {
    unsigned long container_id;
    unsigned int device_id;
} FsPolicyKey;

typedef struct file_policy_key {
    unsigned long container_id;
    unsigned long inode_id;
    unsigned int device_id;
} FilePolicyKey;

#define MINOR_WILDCARD -1L
typedef struct dev_policy_key {
    unsigned long container_id;
    unsigned int major;
    long minor;  // -1 is wildcard
} DevPolicyKey;

typedef struct cap_policy_key {
    unsigned long container_id;
} CapPolicyKey;

typedef struct net_policy_key {
    unsigned long container_id;
} NetPolicyKey;

typedef struct ipc_policy_key {
    unsigned long container_id;
    unsigned long other_container_id;
} IPCPolicyKey;

typedef struct inode_key {
    unsigned long inode_id;
    unsigned int device_id;
} InodeKey;

#endif /* STRUCTS_H */
