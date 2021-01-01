// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include "bpfcontain.h"

/* ========================================================================= *
 * BPF Maps                                                                  *
 * ========================================================================= */

/* Active (containerized) processes */
BPF_LRU_HASH(processes, u32, struct bpfcon_process, BPFCON_MAX_PROCESSES, 0);

/* Active inodes associated with containerized processes */
BPF_LRU_HASH(procfs_inodes, u32, struct inode_key, BPFCON_MAX_PROCESSES, 0);

/* Active containers */
BPF_HASH(containers, u64, struct bpfcon_container, BPFCON_MAX_CONTAINERS, 0);

/* Filesystem policy */
BPF_HASH(fs_allow, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(fs_deny, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* File policy */
BPF_HASH(file_allow, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(file_deny, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Device policy */
BPF_HASH(dev_allow, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(dev_deny, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Capability policy */
BPF_HASH(cap_allow, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(cap_deny, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* ========================================================================= *
 * Helpers                                                                   *
 * ========================================================================= */

/* Add process to the processes map and associate it with @container_id.
 *
 * @pid:          PID of the process.
 * @tgid:         TGID of the process.
 * @container_id: Contaier ID with which to associate the process.
 *
 * return: Pointer to the added process.
 */
static __always_inline struct bpfcon_process *add_process(u32 pid, u32 tgid,
                                                          u64 container_id)
{
    // Initialize a new process
    struct bpfcon_process new_process = {};
    new_process.pid = pid;
    new_process.tgid = tgid;
    new_process.container_id = container_id;
    new_process.in_execve = 0;

    // Cowardly refuse to overwrite an existing process
    if (bpf_map_lookup_elem(&processes, &pid)) {
        return NULL;
    }

    // Add it the processes map
    return bpf_map_lookup_or_try_init(&processes, &pid, &new_process);
}

/* mediated_fs - Returns true if we are mediating the filesystem (i.e. it is
 * _not_ an unnamed device).
 *
 * @inode: A pointer to an inode in the filesystem we are checking.
 *
 * return: True if the filesystem is _not_ unnamed.
 */
static __always_inline int mediated_fs(struct inode *inode)
{
    return !(inode->i_sb->s_flags & SB_NOUSER);
}

/* Convert a kernel file access mask to a BPFContain access, based on the
 * properties of the underlying inode.
 *
 * @inode: A pointer to the inode being accessed.
 * @mask:  Kernel access mask.
 *
 * return: Converted access mask.
 */
static __always_inline u32 mask_to_access(struct inode *inode, int mask)
{
    u32 access = 0;

    // Reading may be converted directly
    if (mask & MAY_READ) {
        access |= BPFCON_MAY_READ;
    }

    // Appending and writing are treated as mutually exclusive
    if (mask & MAY_APPEND) {
        access |= BPFCON_MAY_APPEND;
    } else if (mask & MAY_WRITE) {
        access |= BPFCON_MAY_WRITE;
    }

    // Executing will be BPFCON_MAY_CHDIR if the inode is a directory
    if (mask & MAY_EXEC) {
        if (S_ISDIR(inode->i_mode))
            access |= BPFCON_MAY_CHDIR;
        else
            access |= BPFCON_MAY_EXEC;
    }

    return access;
}

/* ========================================================================= *
 * Filesystem, File, Device Policy                                           *
 * ========================================================================= */

/* Make a policy decision at the filesystem level.
 *
 * @container_id: 64-bit id of the current container
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static __always_inline int do_fs_permission(u64 container_id,
                                            struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;
    struct fs_policy_key key = {};

    key.container_id = container_id;
    key.device_id = new_encode_dev(inode->i_sb->s_dev);

    // If we are allowing the _entire_ access, allow
    u32 *allowed = bpf_map_lookup_elem(&fs_allow, &key);
    if (allowed && ((*allowed & access) == access)) {
        decision |= BPFCON_ALLOW;
    }

    // If we are denying _any part_ of the access, deny
    u32 *denied = bpf_map_lookup_elem(&fs_deny, &key);
    if (denied && (*denied & access)) {
        decision |= BPFCON_DENY;
    }

    return decision;
}

/* Make a policy decision at the file level. Unlike
 * do_fs_permission, this guy checks _individual_ file policy.
 *
 * @container_id: 64-bit id of the current container
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static __always_inline int do_file_permission(u64 container_id,
                                              struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;
    struct file_policy_key key = {};

    key.container_id = container_id;
    key.device_id = new_encode_dev(inode->i_sb->s_dev);
    key.inode_id = inode->i_ino;

    // If we are allowing the _entire_ access, allow
    u32 *allowed = bpf_map_lookup_elem(&file_allow, &key);
    if (allowed && ((*allowed & access) == access)) {
        decision |= BPFCON_ALLOW;
    }

    // If we are denying _any part_ of the access, deny
    u32 *denied = bpf_map_lookup_elem(&file_deny, &key);
    if (denied && (*denied & access)) {
        decision |= BPFCON_DENY;
    }

    return decision;
}

/* Make a policy decision about access to a device.
 *
 * @container_id: 64-bit id of the current container
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static __always_inline int do_dev_permission(u64 container_id,
                                             struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;
    struct dev_policy_key key = {};

    // Look up policy by device major number and container ID
    key.container_id = container_id;
    key.major = MAJOR(inode->i_rdev);

    if (!key.major) {
        return BPFCON_NO_DECISION;
    }

    // If we are allowing the _entire_ access, allow
    u32 *allowed = bpf_map_lookup_elem(&dev_allow, &key);
    if (allowed && ((*allowed & access) == access)) {
        decision |= BPFCON_ALLOW;
    }

    // If we are denying _any part_ of the access, deny
    u32 *denied = bpf_map_lookup_elem(&dev_deny, &key);
    if (denied && (*denied & access)) {
        decision |= BPFCON_DENY;
    }

    return decision;
}

/* Make a policy decision about a task_to_inode file.
 *
 * This function handles the implicit procfs policy. A process can always have
 * full access to procfs entries belonging to the same container.
 *
 * @container_id: 64-bit id of the current container
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static __always_inline int do_procfs_permission(u64 container_id,
                                                struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;

    struct inode_key key = {};
    key.device_id = new_encode_dev(inode->i_sb->s_dev);
    key.inode_id = inode->i_ino;

    // Is this inode in the procfs_inodes map
    u32 *pid = bpf_map_lookup_elem(&procfs_inodes, &key);
    if (!pid)
        return BPFCON_NO_DECISION;

    // Does it belong to our container?
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, pid);
    if (process && process->container_id == container_id) {
        decision |= BPFCON_ALLOW;
    }

    return decision;
}

/* Take all policy decisions together to reach a verdict on inode access.
 *
 * This function should be called and taken as a return value to whatever LSM
 * hooks involve file/inode access.
 *
 * @container_id: 64-bit id of the current container
 * @inode:        A pointer to the inode being accessed
 * @access:       BPFContain access mask
 *
 * return: -EACCES if access is denied or 0 if access is granted.
 */
static int bpfcontain_inode_perm(u64 container_id, struct inode *inode,
                                 u32 access)
{
    int decision = BPFCON_NO_DECISION;
    struct bpfcon_container *container =
        bpf_map_lookup_elem(&containers, &container_id);
    if (!container) {
        return -EACCES;
    }

    // bpf_trace_printk("Accessing on device number %u with uuid %s",
    //                 new_encode_dev(inode->i_sb->s_dev),
    //                 inode->i_sb->s_uuid.b);

    // Do we care about the filesystem?
    if (!mediated_fs(inode))
        return 0;

    // Allow procfs permissions to override denials
    if (do_procfs_permission(container_id, inode, access) == BPFCON_ALLOW)
        return 0;

    // Allow specific file permissions to override denials
    if (do_file_permission(container_id, inode, access) == BPFCON_ALLOW)
        return 0;

    decision |= do_fs_permission(container_id, inode, access);
    decision |= do_dev_permission(container_id, inode, access);

    if (decision & BPFCON_DENY) {
        // bpf_trace_printk("Denying (%lu, %u) due to explicit deny %u",
        //                 inode->i_ino, new_encode_dev(inode->i_sb->s_dev),
        //                 access);
        return -EACCES;
    }

    if (decision & BPFCON_ALLOW)
        return 0;

    if (container->default_deny) {
        // bpf_trace_printk("Denying (%lu, %u) due to implicit deny %u",
        //                 inode->i_ino, new_encode_dev(inode->i_sb->s_dev),
        //                 access);
        return -EACCES;
    }

    return 0;
}

// TODO: Add LSM probes here tomorrow

/* ========================================================================= *
 * Network Policy                                                            *
 * ========================================================================= */

// TODO: Add LSM probes here tomorrow

/* ========================================================================= *
 * Capability Policy                                                         *
 * ========================================================================= */

// TODO: Add LSM probes here tomorrow

/* ========================================================================= *
 * Implicit Policy                                                           *
 * ========================================================================= */

// TODO: Add LSM probes here tomorrow

/* ========================================================================= *
 * Kernel Hardening                                                          *
 * ========================================================================= */

// TODO: Add LSM probes here tomorrow

/* ========================================================================= *
 * Bookkeeping                                                               *
 * ========================================================================= */

// TODO: Add bookkeeping probes here tomorrow

/* ========================================================================= *
 * Uprobe Commands                                                           *
 * ========================================================================= */

/* BPF program endpoint for do_containerize in libbpfcontain.
 *
 * @ret_p: Pointer to the return value of wrapper function.
 * @container_id: Container with which to associate.
 *
 * return: Converted access mask.
 */
SEC("uprobe/do_containerize")
int BPF_KPROBE(do_containerize, int *ret_p, u64 container_id)
{
    int ret = 0;

    // Look up the `pid` and `tgid` of the current process
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // Look up the `container` using `container_id`
    struct bpfcon_container *container =
        bpf_map_lookup_elem(&containers, &container_id);
    // If the container doesn't exist, report an error and bail
    if (!container) {
        ret = -ENOENT;
        goto out;
    }

    // Try to add a process to `processes` with `pid`/`tgid`, associated with
    // `container_id`
    if (!add_process(pid, tgid, container_id)) {
        ret = -EINVAL;
        goto out;
    }

out:
    if (ret_p)
        bpf_probe_write_user(ret_p, &ret, sizeof(ret));

    return 0;
}

/* ========================================================================= *
 * License String                                                            *
 * ========================================================================= */

char LICENSE[] SEC("license") = "GPL";
