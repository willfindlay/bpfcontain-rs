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

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
    // Look up the process using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfcon_process *process = bpf_map_lookup_elem(&processes, &pid);

    // Unconfined
    if (!process)
        return 0;

    // Make an access control decision
    return bpfcontain_inode_perm(process->container_id, file->f_inode,
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
    if (file->i_ino) {
        ret =
            bpfcontain_inode_perm(process->container_id, file, BPFCON_MAY_EXEC);
        if (ret)
            return ret;
    }

    struct inode *executable = bprm->executable->f_inode;
    if (executable->i_ino) {
        ret = bpfcontain_inode_perm(process->container_id, executable,
                                    BPFCON_MAY_EXEC);
        if (ret)
            return ret;
    }

    struct inode *interpreter = bprm->interpreter->f_inode;
    if (interpreter->i_ino) {
        ret = bpfcontain_inode_perm(process->container_id, interpreter,
                                    BPFCON_MAY_EXEC);
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

    return bpfcontain_inode_perm(process->container_id, inode,
                                 BPFCON_MAY_DELETE);
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

    return bpfcontain_inode_perm(process->container_id, inode,
                                 BPFCON_MAY_DELETE);
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

    return bpfcontain_inode_perm(process->container_id, inode,
                                 BPFCON_MAY_CREATE);

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

    return bpfcontain_inode_perm(process->container_id, dir_inode,
                                 BPFCON_MAY_CREATE);

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

    return bpfcontain_inode_perm(process->container_id, dir_inode,
                                 BPFCON_MAY_CREATE);

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

    ret = bpfcontain_inode_perm(process->container_id, dir_inode,
                                BPFCON_MAY_CREATE);
    if (ret)
        return ret;

    ret = bpfcontain_inode_perm(process->container_id, old_inode,
                                BPFCON_MAY_LINK);
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

    ret = bpfcontain_inode_perm(process->container_id, old_inode,
                                BPFCON_MAY_RENAME);
    if (ret)
        return ret;

    ret = bpfcontain_inode_perm(process->container_id, new_dir_inode,
                                BPFCON_MAY_CREATE);
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

    return bpfcontain_inode_perm(process->container_id, inode,
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

    return bpfcontain_inode_perm(process->container_id, inode,
                                 BPFCON_MAY_CHMOD);
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
static __always_inline int mmap_permission(u64 container_id, struct file *file,
                                           unsigned long prot,
                                           unsigned long flags)
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

    return bpfcontain_inode_perm(container_id, file->f_inode, access);
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

    return mmap_permission(process->container_id, file, prot, flags);
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

    return mmap_permission(process->container_id, vma->vm_file, prot,
                           !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0);
}

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
