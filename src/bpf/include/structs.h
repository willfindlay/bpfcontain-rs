// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 15, 2020  William Findlay  Created this.

#ifndef STRUCTS_H
#define STRUCTS_H

#include "defs.h"
#include "user_types.h"

/* ========================================================================= *
 * Container and Process Types                                               *
 * ========================================================================= */

// TODO: use this wherever we have a policy id or a container id
typedef u64 policy_id_t;
typedef u64 container_id_t;

/**
 * process_t - Represents per-task metadata
 * @container_id: id of the container_t that this process belongs to
 * @host_pid: pid of this task in the host's pid namespace
 * @host_tgid: tgid of this task in the host's pid namespace
 * @pid: pid of this task in our own pid namespace
 * @tgid: tgid of this task in our own pid namesapce
 */
typedef struct {
    container_id_t container_id;
    u32 host_pid;
    u32 host_tgid;
    u32 pid;
    u32 tgid;
} process_t;

/**
 * container_t - Represents per-container metadata
 * @policy_id: id of the policy associated with the container
 * @container_id: id of this container
 * @mnt_ns_id: ns id of the container's mount namespace
 * @pid_ns_id: ns id of the container's pid namespace
 * @user_ns_id: ns id of the container's user namespace
 * @refcount: number of processes that are running under this container
 * @tained: is the container tainted?
 * @complain: is the container in complaining mode?
 * @uts_name: the container's UTS name (Docker's notion of container id)
 */
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
    // the user namespace id of this container
    u32 user_ns_id;
    // reference count of the container (how many tasks are running inside it)
    // this should only be incremented and decremented atomically
    u32 refcount;
    // Is the container in a tainted state?
    u8 tainted : 1;
    // Is the container in complain mode?
    u8 complain : 1;
    // often corresponds with container id on the docker side
    char uts_name[16];
} container_t;

/* ========================================================================= *
 * Policy Types                                                              *
 * ========================================================================= */

/**
 * policy_decision_t - Represents a BPFcontain policy decision
 * @BPFCON_NO_DECISION: No policy decision
 * @BPFCON_ALLOW: Allow access
 * @BPFCON_DENY: Deny access
 * @BPFCON_TAINT: Taint the container
 */
typedef enum {
    BPFCON_NO_DECISION = 0x00,
    BPFCON_ALLOW       = 0x01,
    BPFCON_DENY        = 0x02,
    BPFCON_TAINT       = 0x04,
} policy_decision_t;

/**
 * policy_common_t - The common part of a BPFContain policy
 * @default_taint: Should containers under this policy spawn tainted?
 * @complain: Should containers under this policy spawn in complaining mode?
 */
typedef struct {
    u8 default_taint : 1;
    u8 complain : 1;
} __PACKED policy_common_t;

/* ========================================================================= *
 * File Policy                                                               *
 * ========================================================================= */

/**
 * file_permission_t - Access permissions for accessing files
 * @BPFCON_MAY_EXEC: Execute the file
 * @BPFCON_MAY_WRITE: Write to the file (implied append)
 * @BPFCON_MAY_READ: Read from the file
 * @BPFCON_MAY_APPEND: Append to the file
 * @BPFCON_MAY_CHMOD: Change file permissions and owners
 * @BPFCON_MAY_DELETE: Unlink the file
 * @BPFCON_MAY_EXEC_MMAP: Map the file into executable memory
 * @BPFCON_MAY_LINK: Create a hard link to the file
 */
typedef enum {
    BPFCON_MAY_EXEC      = 0x01,
    BPFCON_MAY_WRITE     = 0x02,
    BPFCON_MAY_READ      = 0x04,
    BPFCON_MAY_APPEND    = 0x08,
    BPFCON_MAY_CHMOD     = 0x10,
    BPFCON_MAY_DELETE    = 0x20,
    BPFCON_MAY_EXEC_MMAP = 0x40,
    BPFCON_MAY_LINK      = 0x80,
    BPFCON_MAY_IOCTL     = 0x100,
} file_permission_t;

#define BPFCON_ALL_FS_PERM_MASK                                                \
    (BPFCON_MAY_EXEC | BPFCON_MAY_WRITE | BPFCON_MAY_READ |                    \
     BPFCON_MAY_APPEND | BPFCON_MAY_CHMOD | BPFCON_MAY_DELETE |                \
     BPFCON_MAY_EXEC_MMAP)

#define TASK_INODE_PERM_MASK                                                   \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND |                  \
     BPFCON_MAY_DELETE | BPFCON_MAY_CHMOD)

#define PROC_INODE_PERM_MASK                                                   \
    (BPFCON_MAY_WRITE | BPFCON_MAY_READ | BPFCON_MAY_APPEND)

#define OVERLAYFS_PERM_MASK BPFCON_ALL_FS_PERM_MASK

/**
 * fs_policy_key_t - Key into the filesystem policy map
 * @policy_id: The policy id of this policy
 * @device_id: The device id of the filesystem
 */
typedef struct {
    u64 policy_id;
    u32 device_id;
} __PACKED fs_policy_key_t;

typedef struct {
    u64 policy_id;
    u64 inode_id;
    u32 device_id;
} __PACKED file_policy_key_t;

static const s64 MINOR_WILDCARD = -1;
typedef struct {
    u64 policy_id;
    u32 major;
    s64 minor;
} __PACKED dev_policy_key_t;

typedef struct {
    file_permission_t allow;
    file_permission_t taint;
    file_permission_t deny;
} __PACKED file_policy_val_t;

typedef struct {
    u64 inode_id;
    u32 device_id;
} __PACKED inode_key_t;

/* ========================================================================= *
 * Capabilitity Policy                                                       *
 * ========================================================================= */

/* Tunable capabilities */
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

#define CAP_IMPLICIT_DENY_MASK                                                 \
    (BPFCON_CAP_SYS_MODULE | BPFCON_CAP_SYS_BOOT | BPFCON_CAP_MAC_ADMIN |      \
     BPFCON_CAP_MAC_OVERRIDE | BPFCON_CAP_BPF | BPFCON_CAP_PERFMON |           \
     BPFCON_CAP_AUDIT_READ | BPFCON_CAP_AUDIT_CONTROL)

typedef struct {
    u64 policy_id;
} __PACKED cap_policy_key_t;

typedef struct {
    capability_t allow;
    capability_t taint;
    capability_t deny;
} __PACKED cap_policy_val_t;

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
    BPFCON_NET_CONNECT  = 0x01,
    BPFCON_NET_BIND     = 0x02,
    BPFCON_NET_ACCEPT   = 0x04,
    BPFCON_NET_LISTEN   = 0x08,
    BPFCON_NET_SEND     = 0x10,
    BPFCON_NET_RECV     = 0x20,
    BPFCON_NET_CREATE   = 0x40,
    BPFCON_NET_SHUTDOWN = 0x80,
} net_operation_t;

typedef struct {
    u64 policy_id;
} __PACKED net_policy_key_t;

typedef struct {
    net_operation_t allow;
    net_operation_t taint;
    net_operation_t deny;
} __PACKED net_policy_val_t;

/* ========================================================================= *
 * IPC Policy                                                                *
 * ========================================================================= */

typedef struct {
    u64 policy_id;
    u64 other_policy_id;
} __PACKED ipc_policy_key_t;

typedef struct {
    policy_decision_t decision;
} __PACKED ipc_policy_val_t;

/* ========================================================================= *
 * Audit Types                                                               *
 * ========================================================================= */

/**
 * enum audit_level_t - Specifies the audit level, used to control verbosity in
 * userspace.
 *
 * @FIXME: Add documentation
 */
typedef enum {
    AUDIT__NONE    = 0x0,
    AUDIT_ALLOW    = 0x1, // Audit policy allows
    AUDIT_DENY     = 0x2, // Audit policy denials
    AUDIT_TAINT    = 0x4, // Audit policy taints
    AUDIT_INFO     = 0x6, // Audit info
    AUDIT_WARN     = 0x8, // Audit warnings
    AUDIT__UNKNOWN = 0x10,
} audit_level_t;

#define DEFAULT_AUDIT_LEVEL AUDIT_DENY | AUDIT_TAINT | AUDIT_INFO | AUDIT_WARN
#define should_audit(level) (level & audit_level)

/**
 * enum audit_type_t - Specifies the inner type container in an audit_data_t.
 *
 * @FIXME: Add documentation
 */
typedef enum {
    AUDIT_TYPE_FILE,
    AUDIT_TYPE_CAP,
    AUDIT_TYPE_NET,
    AUDIT_TYPE_IPC,
    AUDIT_TYPE__UNKOWN,
} audit_type_t;

/**
 * struct audit_string_t - Audit data representing a generic string.
 *
 * @FIXME: Add documentation
 * @TODO: This will become useful when bpf_snprintf() lands
 */
typedef struct {
    u8 inner_str[512];
} audit_string_t;

/**
 * struct audit_file_t - Audit data representing a file access.
 *
 * @FIXME: Add documentation
 */
typedef struct {
    file_permission_t access;
    u64 st_ino;
    u32 st_dev;
} audit_file_t;

/**
 * struct audit_cap_t - Audit data representing a capability access.
 *
 * @FIXME: Add documentation
 */
typedef struct {
    capability_t cap;
} audit_cap_t;

/**
 * struct audit_net_t - Audit data representing net access.
 *
 * @FIXME: Add documentation
 */
typedef struct {
    net_operation_t operation;
} audit_net_t;

/**
 * struct audit_ipc_t - Audit data representing ipc access.
 *
 * @FIXME: Add documentation
 */
typedef struct {
    u64 other_policy_id;
    u8 sender; // 1 if we are the sender, 0 otherwise
} audit_ipc_t;

/**
 * struct audit_data_t - Common audit data.
 *
 * @FIXME: Add documentation
 */
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
    };
} audit_data_t;

#endif /* ifndef STRUCTS_H */
