// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_FILE_POLICY_SHARED_H
#define BPFCONTAIN_FILE_POLICY_SHARED_H

#include "vmlinux.h"

#include "defs.h"

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
 * Access permissions for accessing files.
 */
typedef enum {
    // Execute the file
    BPFCON_MAY_EXEC      = (1U << 0),
    // Write to the file (implied append)
    BPFCON_MAY_WRITE     = (1U << 1),
	// Read from the file
    BPFCON_MAY_READ      = (1U << 2),
	// Append to the file
    BPFCON_MAY_APPEND    = (1U << 3),
	// Change file permissions and owners
    BPFCON_MAY_CHMOD     = (1U << 4),
	// Unlink the file
    BPFCON_MAY_DELETE    = (1U << 5),
	// Map the file into executable memory
    BPFCON_MAY_EXEC_MMAP = (1U << 6),
	// Create a hard link to the file
    BPFCON_MAY_LINK      = (1U << 7),
	// Perform an ioctl() on the file
    BPFCON_MAY_IOCTL     = (1U << 8),
} file_permission_t;

/**
 * Policy value for file policies
 */
typedef struct {
	// A vector of file permissions to allow
    file_permission_t allow;
	// A vector of file permissions to taint
    file_permission_t taint;
	// A vector of file permissions to deny
    file_permission_t deny;
} __PACKED file_policy_val_t;

/**
 * Policy key for per-fs policies.
 */
typedef struct {
	// ID of the policy
    u64 policy_id;
	// ID of the filesystem
    u32 device_id;
} __PACKED fs_policy_key_t;

/**
 * Policy key for implicit per-fs policies.
 */
typedef struct {
	// ID of the container
    u64 container_id;
	// ID of the filesystem
    u32 device_id;
} __PACKED fs_implicit_policy_key_t;

/**
 * Policy key for per-file policies.
 */
typedef struct {
	// ID of the policy
    u64 policy_id;
	// Inode number
    u64 inode_id;
	// ID of the filesystem
    u32 device_id;
} __PACKED file_policy_key_t;

/**
 * Special sentinel value reserved as a wildcard for device minor numbers.
 */
static const s64 MINOR_WILDCARD = -1;

/**
 * Policy key for special files (e.g. device drivers)
 */
typedef struct {
	// ID of the policy
    u64 policy_id;
	// Major number of the device driver
    u32 major;
	// Minor number of the device driver or MINOR_WILDCARD
    s64 minor;
} __PACKED dev_policy_key_t;

/**
 * A key that can uniquely identify a file.
 */
typedef struct {
	// Inode number
    u64 inode_id;
	// ID of the filesystem
    u32 device_id;
} __PACKED inode_key_t;

#endif /* ifndef BPFCONTAIN_FILE_POLICY_SHARED_H */
