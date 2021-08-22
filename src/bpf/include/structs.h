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
 * container_status_t - Represents the state of a container
 * @DEFAULT_SHIM: The built-in shim doesn't track state currently
 * @DOCKER_INIT: Runc has started creating a new container
 * @DOCKER_STARTED: Dockerd has reported that the container setup is finished
 */
typedef enum {
    DEFAULT_SHIM = 0,
    DOCKER_INIT = 1000,
    DOCKER_STARTED = 1001,
} container_status_t;

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
    // Is the container in privileged mode?
    u8 privileged : 1;
    // often corresponds with container id on the docker side
    char uts_name[16];
    // Tracks the state of a container
    container_status_t status;
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
    BPFCON_NO_DECISION = 0U,
    BPFCON_ALLOW       = (1U << 0),
    BPFCON_DENY        = (1U << 1),
    BPFCON_TAINT       = (1U << 2),
} policy_decision_t;

/**
 * policy_common_t - The common part of a BPFContain policy
 * @default_taint: Should containers under this policy spawn tainted?
 * @complain: Should containers under this policy spawn in complaining mode?
 */
typedef struct {
    u8 default_taint : 1;
    u8 complain : 1;
    u8 privileged : 1;
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
    BPFCON_MAY_EXEC      = (1U << 0),
    BPFCON_MAY_WRITE     = (1U << 1),
    BPFCON_MAY_READ      = (1U << 2),
    BPFCON_MAY_APPEND    = (1U << 3),
    BPFCON_MAY_CHMOD     = (1U << 4),
    BPFCON_MAY_DELETE    = (1U << 5),
    BPFCON_MAY_EXEC_MMAP = (1U << 6),
    BPFCON_MAY_LINK      = (1U << 7),
    BPFCON_MAY_IOCTL     = (1U << 8),
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
    u64 container_id;
    u32 device_id;
} __PACKED fs_implict_policy_key_t;

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
    BPFCON_CAP_CHOWN              = (1ULL << 0),
    BPFCON_CAP_DAC_OVERRIDE       = (1ULL << 1),
    BPFCON_CAP_DAC_READ_SEARCH    = (1ULL << 2),
    BPFCON_CAP_FOWNER             = (1ULL << 3),
    BPFCON_CAP_FSETID             = (1ULL << 4),
    BPFCON_CAP_KILL               = (1ULL << 5),
    BPFCON_CAP_SETGID             = (1ULL << 6),
    BPFCON_CAP_SETUID             = (1ULL << 7),
    BPFCON_CAP_SETPCAP            = (1ULL << 8),
    BPFCON_CAP_LINUX_IMMUTABLE    = (1ULL << 9),
    BPFCON_CAP_NET_BIND_SERVICE   = (1ULL << 10),
    BPFCON_CAP_NET_BROADCAST      = (1ULL << 11),
    BPFCON_CAP_NET_ADMIN          = (1ULL << 12),
    BPFCON_CAP_NET_RAW            = (1ULL << 13),
    BPFCON_CAP_IPC_LOCK           = (1ULL << 14),
    BPFCON_CAP_IPC_OWNER          = (1ULL << 15),
    BPFCON_CAP_SYS_MODULE         = (1ULL << 16),
    BPFCON_CAP_SYS_RAWIO          = (1ULL << 17),
    BPFCON_CAP_SYS_CHROOT         = (1ULL << 18),
    BPFCON_CAP_SYS_PTRACE         = (1ULL << 19),
    BPFCON_CAP_SYS_PACCT          = (1ULL << 20),
    BPFCON_CAP_SYS_ADMIN          = (1ULL << 21),
    BPFCON_CAP_SYS_BOOT           = (1ULL << 22),
    BPFCON_CAP_SYS_NICE           = (1ULL << 23),
    BPFCON_CAP_SYS_RESOURCE       = (1ULL << 24),
    BPFCON_CAP_SYS_TIME           = (1ULL << 25),
    BPFCON_CAP_SYS_TTY_CONFIG     = (1ULL << 26),
    BPFCON_CAP_MKNOD              = (1ULL << 27),
    BPFCON_CAP_LEASE              = (1ULL << 28),
    BPFCON_CAP_AUDIT_WRITE        = (1ULL << 29),
    BPFCON_CAP_AUDIT_CONTROL      = (1ULL << 30),
    BPFCON_CAP_SETFCAP            = (1ULL << 31),
    BPFCON_CAP_MAC_OVERRIDE       = (1ULL << 32),
    BPFCON_CAP_MAC_ADMIN          = (1ULL << 33),
    BPFCON_CAP_SYSLOG             = (1ULL << 34),
    BPFCON_CAP_WAKE_ALARM         = (1ULL << 35),
    BPFCON_CAP_BLOCK_SUSPEND      = (1ULL << 36),
    BPFCON_CAP_AUDIT_READ         = (1ULL << 37),
    BPFCON_CAP_PERFMON            = (1ULL << 38),
    BPFCON_CAP_BPF                = (1ULL << 39),
    BPFCON_CAP_CHECKPOINT_RESTORE = (1ULL << 40),
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
    BPFCON_NET_WWW = (1U << 0),
    BPFCON_NET_IPC = (1U << 1),
} net_category_t;

/* Network operations */
typedef enum {
    BPFCON_NET_CONNECT  = (1U << 0),
    BPFCON_NET_BIND     = (1U << 1),
    BPFCON_NET_ACCEPT   = (1U << 2),
    BPFCON_NET_LISTEN   = (1U << 3),
    BPFCON_NET_SEND     = (1U << 4),
    BPFCON_NET_RECV     = (1U << 5),
    BPFCON_NET_CREATE   = (1U << 6),
    BPFCON_NET_SHUTDOWN = (1U << 7),
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
 * Signal Policy                                                             *
 * ========================================================================= */

/* Signal Operations access vector for x86
 * TODO: Support other architectures... */
typedef enum {
    BPFCON_SIGCHK    = (1ULL << 0),
    BPFCON_SIGHUP    = (1ULL << 1),
    BPFCON_SIGINT    = (1ULL << 2),
    BPFCON_SIGQUIT   = (1ULL << 3),
    BPFCON_SIGILL    = (1ULL << 4),
    BPFCON_SIGTRAP   = (1ULL << 5),
    BPFCON_SIGABRT   = (1ULL << 6), // SIGIOT has the same number as SIGABRT
    BPFCON_SIGBUS    = (1ULL << 7),
    BPFCON_SIGFPE    = (1ULL << 8),
    BPFCON_SIGKILL   = (1ULL << 9),
    BPFCON_SIGUSR1   = (1ULL << 10),
    BPFCON_SIGSEGV   = (1ULL << 11),
    BPFCON_SIGUSR2   = (1ULL << 12),
    BPFCON_SIGPIPE   = (1ULL << 13),
    BPFCON_SIGALRM   = (1ULL << 14),
    BPFCON_SIGTERM   = (1ULL << 15),
    BPFCON_SIGSTKFLT = (1ULL << 16),
    BPFCON_SIGCHLD   = (1ULL << 17),
    BPFCON_SIGCONT   = (1ULL << 18),
    BPFCON_SIGSTOP   = (1ULL << 19),
    BPFCON_SIGTSTP   = (1ULL << 20),
    BPFCON_SIGTTIN   = (1ULL << 21),
    BPFCON_SIGTTOU   = (1ULL << 22),
    BPFCON_SIGURG    = (1ULL << 23),
    BPFCON_SIGXCPU   = (1ULL << 24),
    BPFCON_SIGXFSZ   = (1ULL << 25),
    BPFCON_SIGVTALRM = (1ULL << 26),
    BPFCON_SIGPROF   = (1ULL << 27),
    BPFCON_SIGWINCH  = (1ULL << 28),
    BPFCON_SIGIO     = (1ULL << 29), // SIGPOLL has the same number as SIGIO
    BPFCON_SIGPWR    = (1ULL << 30),
    BPFCON_SIGSYS    = (1ULL << 31),
} signal_operation_t;

typedef struct {
    u64 sender_id;
    u64 receiver_id;
} __PACKED signal_policy_key_t;

typedef struct {
    signal_operation_t allow;
    signal_operation_t taint;
    signal_operation_t deny;
} __PACKED signal_policy_val_t;

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
 * enum audit_type_t - Specifies the inner type container in an audit_data_t.
 *
 * @FIXME: Add documentation
 */
typedef enum {
    AUDIT_TYPE_FILE,
    AUDIT_TYPE_CAP,
    AUDIT_TYPE_NET,
    AUDIT_TYPE_IPC,
    AUDIT_TYPE_SIGNAL,
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
    u64 other_policy_id; // The other policy ID
    u8 sender;           // 1 if we are the sender, 0 otherwise
} audit_ipc_t;

/**
 * struct audit_signal_t - Audit data representing signal access.
 *
 * @FIXME: Add documentation
 */
typedef struct {
    u64 other_policy_id;       // The other policy ID
    signal_operation_t signal; // The signal number, encoded as an access vector
} audit_signal_t;

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
        audit_signal_t signal;
    };
} audit_data_t;

#endif /* ifndef STRUCTS_H */
