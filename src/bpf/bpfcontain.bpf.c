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

/* Store active filesystems for a mount namespace */
BPF_LRU_HASH(mnt_ns_active_fs, struct mnt_ns_fs, u8, BPFCON_MAX_POLICY, 0);

/* Active containers */
BPF_HASH(containers, u64, struct bpfcon_container, BPFCON_MAX_CONTAINERS, 0);

/* Filesystem policy */
BPF_HASH(fs_allow, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(fs_deny, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(fs_taint, struct fs_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* File policy */
BPF_HASH(file_allow, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(file_deny, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(file_taint, struct file_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Device policy */
BPF_HASH(dev_allow, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(dev_deny, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(dev_taint, struct dev_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Capability policy */
BPF_HASH(cap_allow, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(cap_deny, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(cap_taint, struct cap_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* Network policy */
BPF_HASH(net_allow, struct net_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(net_deny, struct net_policy_key, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(net_taint, struct net_policy_key, u32, BPFCON_MAX_POLICY, 0);

/* IPC policy */
BPF_HASH(ipc_allow, struct ipc_policy_key, u64, BPFCON_MAX_POLICY, 0);
BPF_HASH(ipc_deny, struct ipc_policy_key, u64, BPFCON_MAX_POLICY, 0);
BPF_HASH(ipc_taint, struct ipc_policy_key, u64, BPFCON_MAX_POLICY, 0);

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
static __always_inline struct bpfcon_process *
add_process(u32 pid, u32 tgid, u64 container_id, u8 parent_taint)
{
    // Initialize a new process
    struct bpfcon_process new_process = {};
    new_process.pid = pid;
    new_process.tgid = tgid;
    new_process.container_id = container_id;
    new_process.in_execve = 0;

    struct bpfcon_container *container =
        bpf_map_lookup_elem(&containers, &new_process.container_id);
    if (!container) {
        return NULL;
    }

    new_process.tainted = container->default_taint || parent_taint;

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

/* Check whether two processes are allowed to perform IPC with each other.
 *
 * @process: Pointer to the calling process.
 * @other_pid: Process ID of the other process.
 *
 * return: Policy decision.
 */
static __always_inline policy_decision_t
check_ipc_access(struct bpfcon_process *process, u32 other_pid)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    struct bpfcon_process *other_process =
        bpf_map_lookup_elem(&processes, &other_pid);
    if (!other_process)
        return BPFCON_DENY;

    struct ipc_policy_key key = {};
    key.container_id = process->container_id;
    key.other_container_id = other_process->container_id;

    struct ipc_policy_key other_key = {};
    key.container_id = other_process->container_id;
    key.other_container_id = process->container_id;

    // Allowed access must be mututal
    u32 *allowed = bpf_map_lookup_elem(&ipc_allow, &key);
    u32 *other_allowed = bpf_map_lookup_elem(&ipc_allow, &other_key);
    if (allowed && other_allowed) {
        decision |= BPFCON_ALLOW;
    }

    // The following if-statements need to be mixed like this in order to
    // prevent an unfortunate LLVM optimization that triggers the verifier
    // TODO: Find a more future-proof solution

    // Any denied access results in a denial
    if (bpf_map_lookup_elem(&ipc_deny, &key)) {
        decision |= BPFCON_DENY;
    }

    // Any tainted access results in a taint
    if (bpf_map_lookup_elem(&ipc_taint, &key)) {
        decision |= BPFCON_TAINT;
    }

    // Any denied access results in a denial
    if (bpf_map_lookup_elem(&ipc_deny, &other_key)) {
        decision |= BPFCON_DENY;
    }

    // Any tainted access results in a taint
    if (bpf_map_lookup_elem(&ipc_taint, &other_key)) {
        decision |= BPFCON_TAINT;
    }

    return decision;
}

/* Update a policy map from the eBPF side. This will update the map using the
 * bitwise OR of the value and any existing value with the same key.
 *
 * TODO: Call this function when we start updating policy via uprobes.
 *
 * @map: Pointer to the eBPF policy map.
 * @key: Pointer to the key.
 * @value: Pointer to the desired value.
 *
 * return: Converted access mask.
 */
static __always_inline int
do_update_policy(void *map, const void *key, const u32 *value)
{
    u32 new_value = 0;

    if (!map || !value || !key)
        return -EINVAL;

    u32 *old_value = bpf_map_lookup_elem(map, key);

    if (old_value) {
        new_value = *value | *old_value;
    } else {
        new_value = *value;
    }

    if (!bpf_map_update_elem(map, key, &new_value, 0))
        return -ENOMEM;

    return 0;
}

/* Convert a policy decision into an appropriate action.
 *
 * @map: Pointer to the eBPF policy map.
 *
 * return: Converted access mask.
 */
static __always_inline int
do_policy_decision(struct bpfcon_process *process, policy_decision_t decision)
{
    // Taint process
    if (decision & BPFCON_TAINT) {
        process->tainted = 1;
        goto out;
    }

    // Always deny if denied
    if (decision & BPFCON_DENY) {
        return -EACCES;
    }

    // Always allow if allowed and not denied
    if (decision & BPFCON_ALLOW) {
        return 0;
    }

    struct bpfcon_container *container =
        bpf_map_lookup_elem(&containers, &process->container_id);
    // Something went wrong, assume default deny
    if (!container) {
        return -EACCES;
    }

    // If tainted and default-deny with no policy decision, deny
    if (process->tainted && container->default_deny) {
        return -EACCES;
    }

out:
    return 0;
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
static __always_inline int
do_fs_permission(u64 container_id, struct inode *inode, u32 access)
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

    // If we are tainting _any part_ of the access, taint
    u32 *tainted = bpf_map_lookup_elem(&fs_taint, &key);
    if (tainted && (*tainted & access)) {
        decision |= BPFCON_TAINT;
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
static __always_inline int
do_file_permission(u64 container_id, struct inode *inode, u32 access)
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

    // If we are tainting _any part_ of the access, taint
    u32 *tainted = bpf_map_lookup_elem(&file_taint, &key);
    if (tainted && (*tainted & access)) {
        decision |= BPFCON_TAINT;
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
static __always_inline int
do_dev_permission(u64 container_id, struct inode *inode, u32 access)
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

    // If we are tainting _any part_ of the access, taint
    u32 *tainted = bpf_map_lookup_elem(&dev_taint, &key);
    if (tainted && (*tainted & access)) {
        decision |= BPFCON_TAINT;
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
static __always_inline int
do_procfs_permission(u64 container_id, struct inode *inode, u32 access)
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
static int bpfcontain_inode_perm(struct bpfcon_process *process,
                                 struct inode *inode, u32 access)
{
    int ret = 0;
    policy_decision_t decision = BPFCON_NO_DECISION;

    // Do we care about the filesystem?
    if (!mediated_fs(inode))
        return 0;

    // filesystem and dev permissions
    decision |= do_fs_permission(process->container_id, inode, access);
    decision |= do_dev_permission(process->container_id, inode, access);

    // procfs and file decisions are special, so remember them
    policy_decision_t procfs_decision =
        do_procfs_permission(process->container_id, inode, access);
    decision |= procfs_decision;
    policy_decision_t file_decision =
        do_file_permission(process->container_id, inode, access);
    decision |= file_decision;

    ret = do_policy_decision(process, decision);

    // Allow procfs permissions to override denials
    if (procfs_decision == BPFCON_ALLOW)
        return 0;

    // Allow specific file permissions to override denials
    if (file_decision == BPFCON_ALLOW)
        return 0;

    return ret;
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    // Make an access control decision
    return bpfcontain_inode_perm(process, file->f_inode,
                                 mask_to_access(file->f_inode, mask));
}

/* Enforce policy on execve operations */
SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    int ret = 0;

    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *file = bprm->file->f_inode;
    if (file && file->i_ino) {
        ret = bpfcontain_inode_perm(process, file, BPFCON_MAY_EXEC);
        if (ret)
            return ret;
    }

    struct inode *executable = bprm->executable->f_inode;
    if (executable && executable->i_ino) {
        ret = bpfcontain_inode_perm(process, executable, BPFCON_MAY_EXEC);
        if (ret)
            return ret;
    }

    struct inode *interpreter = bprm->interpreter->f_inode;
    if (interpreter && interpreter->i_ino) {
        ret = bpfcontain_inode_perm(process, interpreter, BPFCON_MAY_EXEC);
        if (ret)
            return ret;
    }

    return 0;
}

/* Mediate access to unlink a path. */
SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *inode = dentry->d_inode;

    return bpfcontain_inode_perm(process, inode, BPFCON_MAY_DELETE);
}

/* Mediate access to unlink a directory. */
SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *inode = dentry->d_inode;

    return bpfcontain_inode_perm(process, inode, BPFCON_MAY_DELETE);
}

/* Mediate access to create a file. */
SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *inode = dir->dentry->d_inode;

    return bpfcontain_inode_perm(process, inode, BPFCON_MAY_CREATE);

    // TODO: also check access based on the type of file

    // TODO: add to the process' list of owned files if permission succeeded
    // _then_ return
}

/* Mediate access to make a directory. */
SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *dir_inode = dir->dentry->d_inode;

    return bpfcontain_inode_perm(process, dir_inode, BPFCON_MAY_CREATE);

    // TODO: add to the process' list of owned files if permission succeeded
    // _then_ return
}

/* Mediate access to make a symlink. */
SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *dir_inode = dir->dentry->d_inode;

    return bpfcontain_inode_perm(process, dir_inode, BPFCON_MAY_CREATE);

    // TODO: add to the process' list of owned files if permission succeeded
    // _then_ return
}

/* Mediate access to make a hard link. */
SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    int ret = 0;

    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *old_inode = old_dentry->d_inode;
    struct inode *dir_inode = new_dir->dentry->d_inode;

    ret = bpfcontain_inode_perm(process, dir_inode, BPFCON_MAY_CREATE);
    if (ret)
        return ret;

    ret = bpfcontain_inode_perm(process, old_inode, BPFCON_MAY_LINK);
    if (ret)
        return ret;

    return 0;
}

/* Mediate access to rename a file. */
SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    int ret = 0;

    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *old_dir_inode = old_dir->dentry->d_inode;
    struct inode *old_inode = old_dentry->d_inode;
    struct inode *new_dir_inode = new_dir->dentry->d_inode;
    struct inode *new_inode = new_dentry->d_inode;

    ret = bpfcontain_inode_perm(process, old_inode, BPFCON_MAY_RENAME);
    if (ret)
        return ret;

    ret = bpfcontain_inode_perm(process, new_dir_inode, BPFCON_MAY_CREATE);
    if (ret)
        return ret;

    return 0;
}

/* Mediate access to truncate a file. */
SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, const struct path *path)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *inode = path->dentry->d_inode;

    return bpfcontain_inode_perm(process, inode,
                                 BPFCON_MAY_WRITE | BPFCON_MAY_SETATTR);
}

/* Mediate access to chmod a file. */
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    struct inode *inode = path->dentry->d_inode;

    return bpfcontain_inode_perm(process, inode, BPFCON_MAY_CHMOD);
}

/* Convert mmap prot and flags into an access vector and then do a permission
 * check.
 *
 * @container_id: Container ID of the process.
 * @file: Pointer to the mmaped file (if not private mapping).
 * @prot: Requested mmap prot.
 * @flags: Requested mmap flags.
 *
 * return: Converted access mask.
 */
static __always_inline int
mmap_permission(struct bpfcon_process *process, struct file *file,
                unsigned long prot, unsigned long flags)
{
    u32 access = 0;

    if (!file)
        return 0;

    if (prot & PROT_READ)
        access |= BPFCON_MAY_READ;

    if ((prot & PROT_WRITE) && !(flags & MAP_PRIVATE))
        access |= BPFCON_MAY_WRITE;

    if ((prot & PROT_EXEC))
        access |= BPFCON_MAY_EXEC_MMAP;

    if (!access)
        return 0;

    return bpfcontain_inode_perm(process, file->f_inode, access);
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return mmap_permission(process, file, prot, flags);
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return mmap_permission(process, vma->vm_file, prot,
                           !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0);
}

/* ========================================================================= *
 * Network Policy                                                            *
 * ========================================================================= */

static u8 family_to_category(int family)
{
    // Note: I think it makes sense to support these protocol families for
    // now. Support for others can be added in the future.
    switch (family) {
        case AF_UNIX:
            return BPFCON_NET_IPC;
            break;
        case AF_INET:
        case AF_INET6:
            return BPFCON_NET_WWW;
            break;
        default:
            return 0;
    }
}

static policy_decision_t
bpfcontain_net_www_perm(struct bpfcon_process *process, u32 access)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    struct net_policy_key key = {};
    key.container_id = process->container_id;

    // If we are allowing the _entire_ access, allow
    u32 *allowed = bpf_map_lookup_elem(&net_allow, &key);
    if (allowed && ((*allowed & access) == access)) {
        decision |= BPFCON_ALLOW;
    }

    // If we are denying _any part_ of the access, deny
    u32 *denied = bpf_map_lookup_elem(&net_deny, &key);
    if (denied && (*denied & access)) {
        decision |= BPFCON_DENY;
    }

    // If we are tainting _any part_ of the access, taint
    u32 *tainted = bpf_map_lookup_elem(&net_taint, &key);
    if (tainted && (*tainted & access)) {
        decision |= BPFCON_TAINT;
    }

    return decision;
}

static policy_decision_t
bpfcontain_net_ipc_perm(struct bpfcon_process *process, u32 access,
                        struct socket *sock)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    u32 pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);
    if (pid) {
        decision |= check_ipc_access(process, pid);
    } else {
        // TODO handle no other PID
    }

    return decision;
}

/* Take all policy decisions together to reach a verdict on network access.
 *
 * This function should be called and taken as a return value to whatever LSM
 * hooks involve network access.
 *
 * @container_id: 64-bit id of the current container
 * @family:       Requested family.
 * @access:       Requested access.
 *
 * return: -EACCES if access is denied or 0 if access is granted.
 */
static int bpfcontain_net_perm(struct bpfcon_process *process, u8 category,
                               u32 access, struct socket *sock)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    if (category == BPFCON_NET_WWW)
        decision = bpfcontain_net_www_perm(process, access);
    else if (category == BPFCON_NET_IPC)
        decision = bpfcontain_net_ipc_perm(process, access, sock);

    return do_policy_decision(process, decision);
}

SEC("lsm/socket_create")
int BPF_PROG(socket_create, int family, int type, int protocol, int kern)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_CREATE, NULL);
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(address->sa_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_BIND, sock);
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(address->sa_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_CONNECT, sock);
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_stream_connect, struct socket *sock, struct socket *other,
             struct socket *newsock)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(AF_UNIX);

    return bpfcontain_net_perm(process, category, BPFCON_NET_CONNECT, sock);
}

SEC("lsm/unix_may_send")
int BPF_PROG(unix_may_send, struct socket *sock, struct socket *other)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(AF_UNIX);

    return bpfcontain_net_perm(process, category, BPFCON_NET_SEND, sock);
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_LISTEN, sock);
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_ACCEPT, sock);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_SEND, sock);
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size,
             int flags)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_RECV, sock);
}

SEC("lsm/socket_shutdown")
int BPF_PROG(socket_shutdown, struct socket *sock, int how)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(process, category, BPFCON_NET_SHUTDOWN, sock);
}

/* ========================================================================= *
 * Capability Policy                                                         *
 * ========================================================================= */

/* Convert a POSIX capability into an "access vector".
 *
 * @cap: Requested POSIX capability
 *
 * return: Converted capability.
 */
static __always_inline u32 cap_to_access(int cap)
{
    if (cap == CAP_NET_BIND_SERVICE) {
        return BPFCON_CAP_NET_BIND_SERVICE;
    }

    if (cap == CAP_NET_RAW) {
        return BPFCON_CAP_NET_RAW;
    }

    if (cap == CAP_NET_BROADCAST) {
        return BPFCON_CAP_NET_BROADCAST;
    }

    if (cap == CAP_DAC_OVERRIDE) {
        return BPFCON_CAP_DAC_OVERRIDE;
    }

    if (cap == CAP_DAC_READ_SEARCH) {
        return BPFCON_CAP_DAC_READ_SEARCH;
    }

    return 0;
}

/* Restrict container capabilities */
SEC("lsm/capable")
int BPF_PROG(capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts)
{
    policy_decision_t decision = BPFCON_NO_DECISION;
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    // Convert cap to an "access vector"
    // (even though only one bit will be on at a time)
    u32 access = cap_to_access(cap);
    if (!access) {  // One of our implicit-deny capbilities
        return -EACCES;
    }

    struct cap_policy_key key = {};
    key.container_id = process->container_id;

    u32 *allowed = bpf_map_lookup_elem(&cap_allow, &key);
    if (allowed && (*allowed & access) == access) {
        decision |= BPFCON_ALLOW;
    }

    u32 *denied = bpf_map_lookup_elem(&cap_deny, &key);
    if (denied && (*denied & access)) {
        decision |= BPFCON_DENY;
    }

    u32 *tainted = bpf_map_lookup_elem(&cap_taint, &key);
    if (tainted && (*tainted & access)) {
        decision |= BPFCON_TAINT;
    }

    return do_policy_decision(process, decision);
}

// TODO COME BACK HERE

/* ========================================================================= *
 * Implicit Policy                                                           *
 * ========================================================================= */

/* Disallow BPF */
SEC("lsm/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow misc. dangerous operations */
SEC("lsm/locked_down")
int BPF_PROG(locked_down, enum lockdown_reason what)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    // We need to allow LOCKDOWN_BPF_READ so our probes work
    if (what == LOCKDOWN_BPF_READ)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_open")
int BPF_PROG(perf_event_open, struct perf_event_attr *attr, int type)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_alloc")
int BPF_PROG(perf_event_alloc, struct perf_event *event)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_read")
int BPF_PROG(perf_event_read, struct perf_event *event)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_write")
int BPF_PROG(perf_event_write, struct perf_event *event)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow access to kernel keyring */
SEC("lsm/key_alloc")
int BPF_PROG(key_alloc, int unused)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow access to kernel keyring */
SEC("lsm/key_permission")
int BPF_PROG(key_permission, int unused)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow access to set system time */
SEC("lsm/settime")
int BPF_PROG(settime, int unused)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow ptrace */
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    return -EACCES;
}

/* Disallow ptrace */
// SEC("lsm/ptrace_traceme")
// int BPF_PROG(ptrace_traceme, int unused)
//{
//    // Look up the process using the current PID
//    u32 pid = bpf_get_current_pid_tgid();
//    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);
//
//    // Unconfined
//    if (!process)
//        return 0;
//
//    return -EACCES;
//}

/* ========================================================================= *
 * Kernel Hardening                                                          *
 * ========================================================================= */

/* It is punishable by death to escalate privileges without going through an
 * execve. */
SEC("fentry/commit_creds")
int fentry_commit_creds(struct cred *new)
{
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    // Check to see if the process is in the middle of an execve
    if (process->in_execve)
        return 0;

    // FIXME: this was killing benign processes
    // bpf_send_signal(SIGKILL);

    return 0;
}

/* ========================================================================= *
 * Bookkeeping                                                               *
 * ========================================================================= */

/* Turn on in_execve bit when we are committing credentials */
SEC("lsm/bprm_committing_creds")
int BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm)
{
    int ret = 0;

    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    process->in_execve = 1;

    return 0;
}

/* Turn off in_execve bit when we are done committing credentials */
SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, struct linux_binprm *bprm)
{
    int ret = 0;

    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    process->in_execve = 0;

    return 0;
}

/* Handle procfs inodes */
SEC("lsm/task_to_inode")
int BPF_PROG(task_to_inode, struct task_struct *task, struct inode *inode)
{
    struct inode_key key = {};

    // Look up the process using the current PID
    u32 pid = task->pid;
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    key.device_id = new_encode_dev(inode->i_sb->s_dev);
    key.inode_id = inode->i_ino;

    bpf_map_update_elem(&procfs_inodes, &key, &pid, 0);

    return 0;
}

/* Propagate a process' container_id to its children */
SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *args)
{
    struct bpfcon_process *process;
    struct bpfcon_process *parent_process;

    u32 ppid = args->parent_pid;
    u32 cpid = args->child_pid;
    u32 ctgid = bpf_get_current_pid_tgid() >> 32;

    // Is the parent confined?
    parent_process = bpf_map_lookup_elem(&processes, &ppid);
    if (!parent_process) {
        return 0;
    }

    // Create the child
    process = add_process(cpid, ctgid, parent_process->container_id,
                          parent_process->tainted);
    if (!process) {
        // TODO log error
    }

    return 0;
}

/* ========================================================================= *
 * Filesystem Mounts                                                         *
 * ========================================================================= */

/* TODO: Updating the mnt_ns_active_fs map makes sense here, but we need to
 * figure out how we are going to delete afterwards. Otherwise, incorrect data
 * will carry between containers as namespace ids / device ids are re-used by
 * the kernel. */
SEC("lsm/sb_set_mnt_opts")
int BPF_PROG(sb_set_mnt_opts, struct super_block *sb, void *mnt_opts,
             unsigned long kern_flags, unsigned long *set_kern_flags)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // struct file_system_type *type = sb->s_type;

    struct mnt_ns_fs key = {};
    key.device_id = new_encode_dev(sb->s_dev);
    key.mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    if (!key.mnt_ns) {
        return 0;
    }

    bpf_printk("alloc mount ns");
    bpf_printk("dev_id = %lu", key.device_id);
    bpf_printk("mnt_ns = %u\n", key.mnt_ns);

    u8 val = 1;
    bpf_map_update_elem(&mnt_ns_active_fs, &key, &val, 0);

    return 0;
}

SEC("lsm/sb_free_security")
int BPF_PROG(sb_free_security, struct super_block *sb)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct mnt_ns_fs key = {};
    key.device_id = new_encode_dev(sb->s_dev);
    key.mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    bpf_printk("free mount ns");
    bpf_printk("dev_id = %lu", key.device_id);
    bpf_printk("mnt_ns = %u\n", key.mnt_ns);

    if (!key.mnt_ns) {
        return 0;
    }

    u8 val = 1;
    bpf_map_delete_elem(&mnt_ns_active_fs, &key);

    return 0;
}

// SEC("lsm/sb_mount")
// int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
//             const char *type, unsigned long flags, void *data)
//{
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//
//    if (flags & MS_REMOUNT) {
//        // TODO handle remount
//    } else if (flags & MS_BIND) {
//        // TODO handle bind
//    } else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)) {
//        // TODO handle change type
//    } else if (flags & MS_MOVE) {
//        // TODO handle mount move
//    } else {
//        u32 inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
//        u32 pid = BPF_CORE_READ(task, pid);
//        char comm[16];
//        bpf_get_current_comm(comm, sizeof(comm));
//        u64 cgroup_id = bpf_get_current_cgroup_id();
//        bpf_printk("  cgroup = %lu", cgroup_id);
//        bpf_printk("  mnt_ns = %u", inum);
//        bpf_printk("     pid = %u", pid);
//        bpf_printk("    comm = %s", comm);
//        bpf_printk("dev_name = %s", dev_name);
//        bpf_printk("    type = %s\n", type);
//        // TODO handle new mount
//    }
//
//    return 0;
//}

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
    if (!add_process(pid, tgid, container_id, 0)) {
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
