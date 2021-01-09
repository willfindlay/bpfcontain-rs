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

/* Possible policy decisions */
typedef enum {
    BPFCON_NO_DECISION = 0x00,
    BPFCON_ALLOW = 0x01,
    BPFCON_DENY = 0x02,
    BPFCON_TAINT = 0x04,
} policy_decision_t;

/* Permissions, partly based on AppArmor */
typedef enum {
    BPFCON_MAY_EXEC = 0x00000001,
    BPFCON_MAY_WRITE = 0x00000002,
    BPFCON_MAY_READ = 0x00000004,
    BPFCON_MAY_APPEND = 0x00000008,
    BPFCON_MAY_CREATE = 0x00000010,
    BPFCON_MAY_DELETE = 0x00000020,
    BPFCON_MAY_RENAME = 0x00000040,
    BPFCON_MAY_SETATTR = 0x00000080,
    BPFCON_MAY_CHMOD = 0x00000100,
    BPFCON_MAY_CHOWN = 0x00000200,
    BPFCON_MAY_LINK = 0x00000400,
    BPFCON_MAY_EXEC_MMAP = 0x00000800,
    BPFCON_MAY_CHDIR = 0x00001000,
} file_permission_t;

/* Tunable capabilities */
typedef enum {
    BPFCON_CAP_NET_BIND_SERVICE = 0x00000001,
    BPFCON_CAP_NET_RAW = 0x00000002,
    BPFCON_CAP_NET_BROADCAST = 0x00000004,
    BPFCON_CAP_DAC_OVERRIDE = 0x00000008,
    BPFCON_CAP_DAC_READ_SEARCH = 0x00000010,
} capability_t;
// Note: Fow now, we only support these capabilities. Most of the other
// capabilities don't really make sense in the context of a container, but may
// be required later for compatibility with other container implementations.

/* Network categories */
typedef enum {
    BPFCON_NET_WWW = 0x01,
    BPFCON_NET_IPC = 0x02,
} net_category_t;

/* Network operations */
typedef enum {
    BPFCON_NET_CONNECT = 0x00000001,
    BPFCON_NET_BIND = 0x00000002,
    BPFCON_NET_ACCEPT = 0x00000004,
    BPFCON_NET_LISTEN = 0x00000008,
    BPFCON_NET_SEND = 0x00000010,
    BPFCON_NET_RECV = 0x00000020,
    BPFCON_NET_CREATE = 0x00000040,
    BPFCON_NET_SHUTDOWN = 0x00000080,
} net_operation_t;

struct bpfcon_container {
    unsigned char default_deny;
    unsigned char default_taint;
};

struct bpfcon_process {
    unsigned long container_id;
    unsigned int pid;
    unsigned int tgid;
    unsigned char in_execve;
    unsigned char tainted;
};

struct mnt_ns_fs {
    // Namespace ID of the mount namespace
    unsigned int mnt_ns;
    // Device ID of the filesystem
    unsigned long device_id;
};

struct fs_policy_key {
    unsigned long container_id;
    unsigned int device_id;
};

struct file_policy_key {
    unsigned long container_id;
    unsigned long inode_id;
    unsigned int device_id;
};

struct dev_policy_key {
    unsigned long container_id;
    unsigned int major;
};

struct cap_policy_key {
    unsigned long container_id;
};

struct net_policy_key {
    unsigned long container_id;
};

struct ipc_policy_key {
    unsigned long container_id;
    unsigned long other_container_id;
};

struct inode_key {
    unsigned long inode_id;
    unsigned int device_id;
};

#endif /* STRUCTS_H */
