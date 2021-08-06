// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

// This must be first
#include <vmlinux.h>

// These must be below vmlinux.h
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

#include <allocator.h>
#include <audit.h>
#include <defs.h>
#include <kernel_defs.h>
#include <map_defs.h>
#include <policy.h>
#include <state.h>

/* ========================================================================= *
 * BPF CO-RE Globals                                                         *
 * ========================================================================= */

// Settings
// TODO: change this to audit_level_t when we add
// support for enums in libbpf-rs
const volatile u32 audit_level;

// Constants
const volatile u32 bpfcontain_pid;
const volatile u32 host_mnt_ns_id;
const volatile u32 host_pid_ns_id;

extern const void init_nsproxy __ksym;
extern const void init_user_ns __ksym;

/* ========================================================================= *
 * Helpers                                                                   *
 * ========================================================================= */

/* mediated_fs - Returns true if we are mediating the filesystem (i.e. it is
 * _not_ an unnamed device).
 *
 * @inode: A pointer to an inode in the filesystem we are checking.
 *
 * return: True if the filesystem is _not_ unnamed.
 */
static __always_inline int mediated_fs(struct inode *inode)
{
    unsigned long flags = inode->i_sb->s_flags;
    return !(flags & SB_NOUSER);
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

    if (!inode)
        return 0;

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

    if (S_ISDIR(inode->i_mode) && (mask & MAY_CHDIR)) {
        access |= BPFCON_MAY_READ;
    }

    // Ignore execute permissions on directories, since we already caught
    // MAY_CHDIR
    if (!S_ISDIR(inode->i_mode) && (mask & MAY_EXEC)) {
        access |= BPFCON_MAY_EXEC;
    }

    return access;
}

/* Convert a file struct to a BPFContain access, based on its mode flags.
 *
 * @file: A pointer to the file struct being accessed.
 *
 * return: Converted access mask.
 */
static __always_inline u32 file_to_access(struct file *file)

{
    u32 access = 0;

    if (file->f_mode & FMODE_READ) {
        access |= BPFCON_MAY_READ;
    }

    if (file->f_mode & FMODE_WRITE) {
        if (file->f_flags & O_APPEND)
            access |= BPFCON_MAY_APPEND;
        else
            access |= BPFCON_MAY_WRITE;
    }

    if (file->f_mode & FMODE_EXEC) {
        access |= BPFCON_MAY_EXEC;
    }

    return access;
}

/* Check whether two containers are allowed to perform IPC with each other.
 *
 * @container: Pointer to the container.
 * @other_pid: Pointer to the other container.
 *
 * return: Policy decision.
 */
static __always_inline policy_decision_t
check_ipc_access(container_t *container, container_t *other_container)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    // Processes are in the same container, so allow
    if (container->policy_id == other_container->policy_id)
        return BPFCON_ALLOW;

    ipc_policy_key_t key = {};

    key.policy_id       = container->policy_id;
    key.other_policy_id = other_container->policy_id;

    ipc_policy_key_t other_key = {};

    key.policy_id       = other_container->policy_id;
    key.other_policy_id = container->policy_id;

    ipc_policy_val_t *val       = bpf_map_lookup_elem(&ipc_policy, &key);
    ipc_policy_val_t *other_val = bpf_map_lookup_elem(&ipc_policy, &other_key);

    if (val && other_val) {
        if ((val->decision & BPFCON_ALLOW) &&
            (other_val->decision & BPFCON_ALLOW))
            decision |= BPFCON_ALLOW;

        if ((val->decision & BPFCON_DENY) ||
            (other_val->decision & BPFCON_DENY))
            decision |= BPFCON_DENY;

        if ((val->decision & BPFCON_TAINT) ||
            (other_val->decision & BPFCON_TAINT))
            decision |= BPFCON_TAINT;
    } else if (val) {
        if (val->decision & BPFCON_DENY)
            decision |= BPFCON_DENY;

        if (val->decision & BPFCON_TAINT)
            decision |= BPFCON_TAINT;
    } else if (other_val) {
        if (other_val->decision & BPFCON_DENY)
            decision |= BPFCON_DENY;

        if (other_val->decision & BPFCON_TAINT)
            decision |= BPFCON_TAINT;
    }

    return decision;
}

/* Convert a policy decision into an appropriate action.
 *
 * return: Converted access mask.
 */
static __always_inline int do_policy_decision(container_t *container,
                                              policy_decision_t decision,
                                              bool ignore_taint)
{
    bool tainted = container->tainted | ignore_taint;

    // Taint container
    if (decision & BPFCON_TAINT) {
        container->tainted = 1;
    }

    // Always deny if denied
    if (decision & BPFCON_DENY && !container->complain) {
        return -EACCES;
    }

    // Always allow if allowed and not denied
    if (decision & BPFCON_ALLOW) {
        return 0;
    }

    // If tainted with no policy decision, deny
    if (tainted && !container->complain) {
        return -EACCES;
    }

    return 0;
}

/* Get a pointer to a struct mount from a struct vfsmount.
 *
 * @mnt: Pointer to the struct vfsmount.
 *
 * return: Pointer to the containing mount struct.
 */
static __always_inline struct mount *get_real_mount(const struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

/* Get the mount namespace id for the current task.
 *
 * return: Mount namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_mnt_ns_id()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return task->nsproxy->mnt_ns->ns.inum;
}

/* Get the pid namespace id for the current task.
 *
 * return: Pid namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_pid_ns_id()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return task->thread_pid->numbers[0].ns->ns.inum;
}

/* Get the user namespace id for the current task.
 *
 * return: user namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_user_ns_id()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return task->cred->user_ns->ns.inum;
}

/* Get the user namespace id for an inode.
 *
 * return: user namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_inode_user_ns_id(struct inode *inode)
{
    return inode->i_sb->s_user_ns->ns.inum;
}

/* Get the uts namespace name for the current task. */
static __always_inline void get_current_uts_name(char *dest, size_t size)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    char *uts_name = task->nsproxy->uts_ns->name.nodename;
    if (uts_name)
        bpf_probe_read_str(dest, size, uts_name);
}

/* Get the mount namespace id for @file.
 *
 * @file: Pointer to a file struct.
 *
 * return: Mount namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_file_mnt_ns_id(const struct file *file)
{
    struct vfsmount *vfsmnt = file->f_path.mnt;
    if (!vfsmnt)
        return 0;

    struct mount *mnt = get_real_mount(vfsmnt);
    if (!mnt)
        return 0;

    return mnt->mnt_ns->ns.inum;
}

/* Get the mount namespace id for @path.
 *
 * @path: Pointer to a path struct.
 *
 * return: Mount namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_path_mnt_ns_id(const struct path *path)
{
    struct vfsmount *vfsmnt = path->mnt;
    if (!vfsmnt)
        return 0;

    struct mount *mnt = get_real_mount(vfsmnt);
    if (!mnt)
        return 0;

    return mnt->mnt_ns->ns.inum;
}

/* Get a pointer to the proc_inode struct associated with inode.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   A pointer to the proc_inode, if one exists
 *   Otherwise, returns NULL
 */
static __always_inline struct proc_inode *get_proc_inode(struct inode *inode)
{
    return container_of(inode, struct proc_inode, vfs_inode);
}

/* Get the PID associated with an inode in procfs.
 *
 * @inode: Pointer to the inode.
 *
 * return:
 *   A pid, if one exists
 *   Otherwise, returns 0
 */
static __always_inline u32 get_proc_pid(struct inode *inode)
{
    struct proc_inode *proc_inode = get_proc_inode(inode);
    if (!proc_inode)
        return 0;

    return BPF_CORE_READ(proc_inode, pid, numbers[0].nr);
}

/* Get the PID of the @task according to its _pid namespace_.
 *
 * Params:
 *    @task: pointer to the task struct
 *
 * Return:
 *    A 64-bit integer with the tgid in the upper 32 bits and the pid in the
 *    lower 32 bits if successful.
 */
static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    u32 level = task->nsproxy->pid_ns_for_children->level;
    return (BPF_CORE_READ(task, thread_pid, numbers[level].nr));
}

/* Get the TGID of the @task according to its _pid namespace_.
 *
 * Params:
 *    @task: pointer to the task struct
 *
 * Return:
 *    A 64-bit integer with the tgid in the upper 32 bits and the pid in the
 *    lower 32 bits if successful.
 */
static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    u32 level = task->nsproxy->pid_ns_for_children->level;
    return (BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr));
}

/* Get the PID and TGID of the @task according to its _pid namespace_.
 *
 * Params:
 *    @task: pointer to the task struct
 *
 * Return:
 *    A 64-bit integer with the tgid in the upper 32 bits and the pid in the
 *    lower 32 bits if successful.
 */
static __always_inline u64 get_task_ns_pid_tgid(struct task_struct *task)
{
    return (u64)get_task_ns_tgid(task) << 32 | get_task_ns_pid(task);
}

/* Get the PID of the current task according to its _pid namespace_.
 *
 * Return:
 *    A 32 bit pid
 *    Otherwise, 0
 */
static __always_inline u32 get_current_ns_pid()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return get_task_ns_pid(task);
}

/* Get the TGID of the current task according to its _pid namespace_.
 *
 * Return:
 *    A 32 bit tgid
 *    Otherwise, 0
 */
static __always_inline u32 get_current_ns_tgid()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return get_task_ns_tgid(task);
}

/* Get the PID and TGID of the current task according to its _pid namespace_.
 *
 * Return:
 *    A 64-bit integer with the tgid in the upper 32 bits and the pid in the
 *    lower 32 bits if successful.
 */
static __always_inline u64 get_current_ns_pid_tgid()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return get_task_ns_pid_tgid(task);
}

/* Returns true if the current process is under the host nsproxy. That is, if it
 * has no special namespace associations.
 *
 * This can serve as a proxy for whether or not we are in a "container" as
 * defined by systems like docker, k8s, etc.
 *
 * Return:
 *    True if we are under init_nsproxy
 *    False otherwise
 */
static __always_inline bool under_init_nsproxy()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return (long)&init_nsproxy == (long)task->nsproxy;
}

/* Get a pointer to the path struct that contains @dentry.
 *
 * @dentry: Pointer to the dentry struct.
 *
 * return:
 *   A pointer to the path struct, if one exists
 *   Otherwise, returns NULL
 */
static __always_inline struct path *get_dentry_path(const struct dentry *dentry)
{
    return container_of(dentry, struct path, dentry);
}

/* Returns true if @inode is a device.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   True if inode is a device
 *   Otherwise false
 */
static __always_inline bool inode_is_device(const struct inode *inode)
{
    return S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode);
}

/* Returns true if @inode is a socket.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   True if inode is a socket
 *   Otherwise false
 */
static __always_inline bool inode_is_sock(const struct inode *inode)
{
    return S_ISSOCK(inode->i_mode);
}

/* Returns true if @inode is a directory.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   True if inode is a directory
 *   Otherwise false
 */
static __always_inline bool inode_is_dir(const struct inode *inode)
{
    return S_ISDIR(inode->i_mode);
}

/* Returns true if @inode is a fifo.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   True if inode is a fifo
 *   Otherwise false
 */
static __always_inline bool inode_is_fifo(const struct inode *inode)
{
    return S_ISFIFO(inode->i_mode);
}

/* Returns true if @inode is a symbolic link.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   True if inode is a symbolic link
 *   Otherwise false
 */
static __always_inline bool inode_is_symlink(const struct inode *inode)
{
    return S_ISLNK(inode->i_mode);
}

/* Returns true if @inode is a regular file.
 *
 * @inode: Pointer to the inode struct.
 *
 * return:
 *   True if inode is a regular file
 *   Otherwise false
 */
static __always_inline bool inode_is_regular(const struct inode *inode)
{
    return S_ISREG(inode->i_mode);
}

/* Get the overlayfs inode associated with an inode in an overlayfs.
 *
 * @inode: Pointer to the inode.
 *
 * return:
 *   A pointer to the overlay_inode, if one exists
 *   Otherwise, returns NULL
 */
// static __always_inline struct ovl_inode *
// get_overlayfs_inode(struct inode *inode)
//{
//    int zero = 0;
//
//    struct ovl_inode *_ovl_inode =
//        container_of(inode, struct ovl_inode, vfs_inode);
//
//    struct ovl_inode *ovl_inode = bpf_map_lookup_elem(&__ovl_inode_init,
//    &zero);
//
//    if (!ovl_inode)
//        return NULL;
//
//    bpf_probe_read(ovl_inode, sizeof(struct ovl_inode), _ovl_inode);
//
//    return ovl_inode;
//}

// FIXME: This is causing verifier to complain about !read_ok
// static __always_inline struct inode *
// get_overlayfs_lower_inode(struct inode *inode)
//{
//    int zero = 0;
//
//    struct ovl_inode *ovl_inode = get_overlayfs_inode(inode);
//    if (!ovl_inode)
//        return NULL;
//
//    struct inode *lower_inode = bpf_map_lookup_elem(&__inode_init, &zero);
//    if (!lower_inode)
//        return NULL;
//
//    bpf_probe_read(lower_inode, sizeof(struct inode), ovl_inode->lower);
//
//    return lower_inode;
//}

/* Filter an inode by the filesystem magic number of its superblock.
 *
 * @inode: Pointer to the inode.
 *
 * return:
 *   A pid, if one exists
 *   Otherwise, returns 0
 */
static __always_inline bool filter_inode_by_magic(struct inode *inode,
                                                  u64 magic)
{
    if (inode->i_sb->s_magic == magic)
        return true;

    return false;
}

/* Add an inode to the list of the containers' owned inodes.
 *
 * @container: Pointer to the container.
 * @inode: Pointer to the inode.
 *
 * return: Does not return.
 */
static __always_inline void add_inode_to_container(const container_t *container,
                                                   struct inode *inode)
{
    container_id_t *id = bpf_inode_storage_get(&task_inodes, (void *)inode, 0,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (id)
        *id = container->container_id;
}

/* Add a new process to a container.
 *
 * Params:
 *    @container: A pointer to the container.
 *    @host_pid_tgid: Host pid and tgid of the process.
 *    @pid_tgid: Namespace pid and tgid of the process.
 *
 * Returns:
 *    A pointer to the newly created process, if successful
 *    Otherwise, NULL
 */
static process_t *add_process_to_container(container_t *container,
                                           u64 host_pid_tgid, u64 pid_tgid)
{
    // Null check on container
    if (!container)
        return NULL;

    // Allocate a new process
    process_t *process = new_process_t();
    if (!process)
        return NULL;

    process->container_id = container->container_id;
    process->host_pid     = host_pid_tgid;
    process->host_tgid    = (host_pid_tgid >> 32);
    process->pid          = pid_tgid;
    process->tgid         = (pid_tgid >> 32);

    // Add the process to the processes map
    bpf_map_update_elem(&processes, &process->host_pid, process, BPF_NOEXIST);

    // Look up the result
    process = bpf_map_lookup_elem(&processes, &process->host_pid);
    if (!process)
        return NULL;

    // Increment container's refcount
    lock_xadd(&container->refcount, 1);

    return process;
}

/* Remove a process from a container.
 *
 * Params:
 *    @container: A pointer to the container.
 *    @host_pid: Host pid of the process.
 */
static void remove_process_from_container(container_t *container, u32 host_pid)
{
    // Null check on container
    if (!container)
        return;

    // Decrement container's refcount
    lock_xadd(&container->refcount, -1);

    // Delete the container
    if (container->refcount == 0) {
        bpf_map_delete_elem(&containers, &container->container_id);
    }

    // Delete the process
    bpf_map_delete_elem(&processes, &host_pid);
}

/* Start a new container.
 *
 * Params:
 *    @policy_id: The policy id to associated with the container
 *
 * Returns:
 *    A pointer to the newly created container, if successful
 *    Otherwise, NULL
 */
static container_t *start_container(policy_id_t policy_id, bool tainted)
{
    // Allocate a new container
    container_t *container = new_container_t();
    if (!container) {
        // TODO: Log that an error occurred
        return NULL;
    }

    // Look up common part of the policy
    policy_common_t *common = bpf_map_lookup_elem(&policy_common, &policy_id);
    if (!common) {
        // TODO: Log that an error occurred
        return NULL;
    }

    u32 pid = bpf_get_current_pid_tgid();

    // Initialize the container
    // The container id is a 64 bit integer where the upper 32 bits are a random
    // integer and the lower 32 bits are the _host_ pid of the initial process.
    container->container_id = ((u64)bpf_get_prandom_u32() << 32 | pid);
    // The mount ns id of the container
    container->mnt_ns_id = get_current_mnt_ns_id();
    // The pid ns id of the container
    container->pid_ns_id = get_current_pid_ns_id();
    // The user ns id of the container
    container->user_ns_id = get_current_user_ns_id();
    // The id of the bpfcontain policy that should be associated with the
    // container
    container->policy_id = policy_id;
    // The container's refcount (number of associated processes)
    // This value is _only_ modified atomically
    container->refcount = 0;
    // Is the container tainted?
    container->tainted = tainted || common->default_taint;
    // Is the container in complaining mode?
    container->complain = common->complain;
    // The UTS namespace hostname of the container. In docker and kubernetes,
    // this usually corresponds with their notion of a container id.
    get_current_uts_name(container->uts_name, sizeof(container->uts_name));

    // In a different namespace
    if (!under_init_nsproxy()) {
        // TODO do we want to do something different here?
    }

    if (!add_process_to_container(container, bpf_get_current_pid_tgid(),
                                  get_current_ns_pid_tgid())) {
        // TODO: Log that an error occurred
        return NULL;
    }

    // Add the container to the containers map
    bpf_map_update_elem(&containers, &container->container_id, container,
                        BPF_NOEXIST);

    // Look up the result and return it
    return bpf_map_lookup_elem(&containers, &container->container_id);
}

/* Get container of a process with a host pid of @pid.
 *
 * Params:
 *    @pid: The host pid
 *
 * Returns:
 *    A pointer to the container, if one exists
 *    Otherwise, NULL
 */
static __always_inline container_t *get_container_by_host_pid(u32 pid)
{
    process_t *process = bpf_map_lookup_elem(&processes, &pid);
    if (!process)
        return NULL;

    return bpf_map_lookup_elem(&containers, &process->container_id);
}

/* ========================================================================= *
 * Filesystem, File, Device Policy                                           *
 * ========================================================================= */

/* Make a policy decision at the filesystem level.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static int do_fs_permission(container_t *container, struct inode *inode,
                            u32 access)
{
    int decision = BPFCON_NO_DECISION;

    fs_policy_key_t key = {};

    key.policy_id = container->policy_id;
    key.device_id = new_encode_dev(inode->i_sb->s_dev);

    file_policy_val_t *val = bpf_map_lookup_elem(&fs_policy, &key);
    // Entire access must match to allow
    if (val && (val->allow & access) == access)
        decision |= BPFCON_ALLOW;
    // Any part of access must match to taint
    if (val && (val->taint & access))
        decision |= BPFCON_TAINT;
    // Any part of access must match to deny
    if (val && (val->deny & access))
        decision |= BPFCON_DENY;

    return decision;
}

/* Make a policy decision at the file level. Unlike
 * do_fs_permission, this guy checks _individual_ file policy.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static int do_file_permission(container_t *container, struct inode *inode,
                              u32 access)
{
    int decision = BPFCON_NO_DECISION;

    file_policy_key_t key = {};

    key.policy_id = container->policy_id;
    key.device_id = new_encode_dev(inode->i_sb->s_dev);
    key.inode_id  = inode->i_ino;

    file_policy_val_t *val = bpf_map_lookup_elem(&file_policy, &key);
    // Entire access must match to allow
    if (val && (val->allow & access) == access)
        decision |= BPFCON_ALLOW;
    // Any part of access must match to taint
    if (val && (val->taint & access))
        decision |= BPFCON_TAINT;
    // Any part of access must match to deny
    if (val && (val->deny & access))
        decision |= BPFCON_DENY;

    return decision;
}

/* Make a policy decision about access to a device.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static int do_dev_permission(container_t *container, struct inode *inode,
                             u32 access)
{
    int decision = BPFCON_NO_DECISION;

    dev_policy_key_t key = {};

    // Look up policy by device major number and policy ID
    key.policy_id = container->policy_id;
    key.major     = MAJOR(inode->i_rdev);

    // Not a device driver
    if (!key.major) {
        return BPFCON_NO_DECISION;
    }

    /*
     * Try with minor = -1 first (wildcard)
     */
    key.minor = MINOR_WILDCARD;

    file_policy_val_t *val = bpf_map_lookup_elem(&dev_policy, &key);
    if (!val)
        goto use_minor;

    // Entire access must match to allow
    if ((val->allow & access) == access)
        decision |= BPFCON_ALLOW;
    // Any part of access must match to taint
    if ((val->taint & access))
        decision |= BPFCON_TAINT;
    // Any part of access must match to deny
    if ((val->deny & access))
        decision |= BPFCON_DENY;

    /*
     * Try with minor = i_rdev's minor second
     */
use_minor:
    key.minor = MINOR(inode->i_rdev);
    val       = bpf_map_lookup_elem(&dev_policy, &key);
    if (!val)
        return BPFCON_DENY;

    // Entire access must match to allow
    if ((val->allow & access) == access)
        decision |= BPFCON_ALLOW;
    // Any part of access must match to taint
    if ((val->taint & access))
        decision |= BPFCON_TAINT;
    // Any part of access must match to deny
    if ((val->deny & access))
        decision |= BPFCON_DENY;

    return decision;
}

/* Make a policy decision about a procfs file.
 *
 * This function handles the implicit procfs policy. A container can always have
 * full access to procfs entries belonging to the same container.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static int do_procfs_permission(container_t *container, struct inode *inode,
                                u32 access)
{
    int decision = BPFCON_NO_DECISION;

    if (!inode)
        return BPFCON_NO_DECISION;

    // Not in procfs
    if (!filter_inode_by_magic(inode, PROC_SUPER_MAGIC))
        return BPFCON_NO_DECISION;

    // Get the pid from procfs
    u32 pid = get_proc_pid(inode);
    if (!pid)
        return BPFCON_NO_DECISION;

    // Does it belong to our container?
    container_t *inode_container = get_container_by_host_pid(pid);
    if (inode_container &&
        inode_container->container_id == container->container_id &&
        (access & PROC_INODE_PERM_MASK) == access) {
        decision |= BPFCON_ALLOW;
    }

    return decision;
}

/* Make a policy decision about a file in overlayfs.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static int do_overlayfs_permission(container_t *container, struct inode *inode,
                                   u32 access)
{
    if (!inode)
        return BPFCON_NO_DECISION;

    // Not in an overlayfs
    if (!filter_inode_by_magic(inode, OVERLAYFS_SUPER_MAGIC))
        return BPFCON_NO_DECISION;

    u32 overlayfs_user_ns_id = get_inode_user_ns_id(inode);

    // TODO: check if we are in root user namespace (should be NO_DECISION)
    if (overlayfs_user_ns_id == PROC_USER_INIT_INO)
        return BPFCON_NO_DECISION;

    if (overlayfs_user_ns_id == container->user_ns_id)
        return BPFCON_ALLOW;

    return BPFCON_NO_DECISION;
}

/* Make an implicit policy decision about a file or directory belonging to
 * (created by) a policy.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static int do_task_inode_permission(container_t *container, struct inode *inode,
                                    u32 access)
{
    int decision = BPFCON_NO_DECISION;

    if (!inode)
        return BPFCON_NO_DECISION;

    // Is this inode in the procfs_inodes map
    container_id_t *id = bpf_inode_storage_get(&task_inodes, inode, 0, 0);
    if (!id)
        return BPFCON_NO_DECISION;

    // Does it belong to our policy?
    if (container && container->container_id == *id) {
        // Apply TASK_INODE_PERM_MASK for implicit privileges
        if ((access & TASK_INODE_PERM_MASK) == access)
            decision |= BPFCON_ALLOW;
    }

    return decision;
}

/* Take all policy decisions together to reach a verdict on inode access.
 *
 * This function should be called and taken as a return value to whatever LSM
 * hooks involve file/inode access.
 *
 * @policy_id: 64-bit id of the current policy
 * @inode:        A pointer to the inode being accessed
 * @access:       BPFContain access mask
 *
 * return: -EACCES if access is denied or 0 if access is granted.
 */
static int bpfcontain_inode_perm(container_t *container, struct inode *inode,
                                 u32 access)
{
    bool super_allow = false;
    int ret          = 0;
    audit_data_t *event;
    policy_decision_t decision = BPFCON_NO_DECISION;

    if (!inode)
        return 0;

    if (!access)
        return 0;

    // Do we care about the filesystem?
    if (!mediated_fs(inode))
        return 0;

    // TODO we want to use this to get the underlying inode in overlay
    // filesystems
    // if (filter_inode_by_magic(inode, OVERLAYFS_SUPER_MAGIC)) {
    //     // TODO
    // }

    // device-specific permissions
    if (inode_is_device(inode)) {
        decision = do_dev_permission(container, inode, access);
        ret      = do_policy_decision(container, decision, true);
        goto out;
    }

    // ipc and network permissions will catch this,
    // so we can allow reads, writes, and appends on sockets here
    if (inode_is_sock(inode) && (access & ~(BPFCON_MAY_READ | BPFCON_MAY_WRITE |
                                            BPFCON_MAY_APPEND)) == 0) {
        ret = do_policy_decision(container, BPFCON_ALLOW, false);
        goto out;
    }

    // per-file allow should override per filesystem deny
    decision |= do_procfs_permission(container, inode, access);
    decision |= do_task_inode_permission(container, inode, access);
    decision |= do_file_permission(container, inode, access);

    // per-file allow should override per filesystem deny
    if ((decision & BPFCON_ALLOW) && !(decision & BPFCON_DENY))
        super_allow = true;

    // filesystem-level permissions
    decision |= do_fs_permission(container, inode, access);
    decision |= do_overlayfs_permission(container, inode, access);

    // per-file allow should override per filesystem deny
    if (super_allow)
        decision &= (~BPFCON_DENY);

    ret = do_policy_decision(container, decision, false);

out:
    // Submit an audit event
    event = alloc_audit_event(
        container->policy_id, AUDIT_TYPE_FILE,
        decision_to_audit_level(decision, container->tainted));
    if (event) {
        event->file.access = access;
        event->file.st_ino = inode->i_ino;
        event->file.st_dev = new_encode_dev(inode->i_sb->s_dev);
        submit_audit_event(event);
    }

    return ret;
}

SEC("lsm/inode_init_security")
int BPF_PROG(inode_init_security, struct inode *inode, struct inode *dir,
             const struct qstr *qstr, const char **name, void **value,
             size_t *len)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Add the newly created inode to the container's list of inodes.
    // This will then be used as a sensible default when computing
    // permissions.add_inode_to_container(container, inode);

    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Make an access control decision
    return bpfcontain_inode_perm(container, inode, mask_to_access(inode, mask));
}

SEC("lsm/file_receive")
int BPF_PROG(file_receive, struct file *file)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Make an access control decision
    return bpfcontain_inode_perm(container, file->f_inode,
                                 file_to_access(file));
}

/* Enforce policy on execve operations */
SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    int ret = 0;

    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    struct file *file = bprm->file;
    if (file) {
        ret = bpfcontain_inode_perm(container, file->f_inode, BPFCON_MAY_EXEC);
        if (ret)
            return ret;
    }

    return 0;
}

/* Mediate access to unlink a path. */
SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, dentry->d_inode, BPFCON_MAY_DELETE);
}

/* Mediate access to unlink a directory. */
SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, dentry->d_inode, BPFCON_MAY_DELETE);
}

/* Mediate access to create a file. */
SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int ret = bpfcontain_inode_perm(container, dir->dentry->d_inode,
                                    BPFCON_MAY_APPEND);
    if (ret)
        return ret;

    // TODO: handle non-zero dev values (allow if we have access to the device
    // in question?)

    return 0;
}

/* Mediate access to make a directory. */
SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, dir->dentry->d_inode,
                                 BPFCON_MAY_APPEND);
}

/* Mediate access to make a symlink. */
SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, dir->dentry->d_inode,
                                 BPFCON_MAY_APPEND);
}

/* Mediate access to make a hard link. */
SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    int ret = 0;

    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    ret = bpfcontain_inode_perm(container, new_dir->dentry->d_inode,
                                BPFCON_MAY_APPEND);
    if (ret)
        return ret;

    return bpfcontain_inode_perm(container, old_dentry->d_inode,
                                 BPFCON_MAY_LINK);
}

/* Mediate access to rename a file. */
SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    int ret = 0;

    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    struct inode *old_dir_inode = old_dir->dentry->d_inode;
    struct inode *old_inode     = old_dentry->d_inode;
    struct inode *new_dir_inode = new_dir->dentry->d_inode;
    struct inode *new_inode     = new_dentry->d_inode;

    ret = bpfcontain_inode_perm(container, old_inode, BPFCON_MAY_DELETE);
    if (ret)
        return ret;

    ret = bpfcontain_inode_perm(container, new_dir_inode, BPFCON_MAY_APPEND);
    if (ret)
        return ret;

    return 0;
}

/* Mediate access to truncate a file. */
SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, const struct path *path)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, path->dentry->d_inode,
                                 BPFCON_MAY_WRITE);
}

/* Mediate access to chmod a file. */
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, path->dentry->d_inode,
                                 BPFCON_MAY_CHMOD);
}

/* Convert mmap prot and flags into an access vector and then do a permission
 * check.
 *
 * @file: Pointer to the mmaped file (if not private mapping).
 * @prot: Requested mmap prot.
 * @flags: Requested mmap flags.
 *
 * return: Converted access mask.
 */
static int mmap_permission(container_t *container, struct file *file,
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

    return bpfcontain_inode_perm(container, file->f_inode, access);
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return mmap_permission(container, file, prot, flags);
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return mmap_permission(container, vma->vm_file, prot,
                           !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0);
}

SEC("lsm/file_ioctl")
int BPF_PROG(file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, file->f_inode, BPFCON_MAY_IOCTL);
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
    case AF_UNSPEC:
        return BPFCON_NET_WWW;
        break;
    default:
        return 0;
    }
}

static policy_decision_t bpfcontain_net_www_perm(container_t *container,
                                                 u32 access)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    net_policy_key_t key = {};

    key.policy_id = container->policy_id;

    net_policy_val_t *val = bpf_map_lookup_elem(&net_policy, &key);
    // Entire access must match to allow
    if (val && (val->allow & access) == access)
        decision |= BPFCON_ALLOW;
    // Any part of access must match to taint
    if (val && (val->taint & access))
        decision |= BPFCON_TAINT;
    // Any part of access must match to deny
    if (val && (val->deny & access))
        decision |= BPFCON_DENY;

    // Submit an audit event
    audit_data_t *event = alloc_audit_event(
        container->policy_id, AUDIT_TYPE_NET,
        decision_to_audit_level(decision, container->tainted));
    if (event) {
        event->net.operation = access;
        submit_audit_event(event);
    }

    return decision;
}

static policy_decision_t
bpfcontain_net_ipc_perm(container_t *container, u32 access, struct socket *sock)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    u32 other_pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);

    // We want to allow creating and listening over Unix sockets
    if ((access & (BPFCON_NET_CREATE | BPFCON_NET_LISTEN | BPFCON_NET_BIND)) ==
        access)
        return BPFCON_ALLOW;

    container_t *other_container = get_container_by_host_pid(other_pid);
    if (other_container) {
        decision |= check_ipc_access(container, other_container);

        // Submit an audit event
        audit_data_t *event = alloc_audit_event(
            container->policy_id, AUDIT_TYPE_IPC,
            decision_to_audit_level(decision, container->tainted));
        if (event) {
            event->ipc.other_policy_id = other_container->policy_id;
            event->ipc.sender          = 1;
            submit_audit_event(event);
        }
    } else {
        // Deny when there is no container peer, for now...
        decision = BPFCON_DENY;
    }

    return decision;
}

/* Take all policy decisions together to reach a verdict on network access.
 *
 * This function should be called and taken as a return value to whatever LSM
 * hooks involve network access.
 *
 * @policy_id: 64-bit id of the current policy
 * @family:       Requested family.
 * @access:       Requested access.
 *
 * return: -EACCES if access is denied or 0 if access is granted.
 */
static int bpfcontain_net_perm(container_t *container, u8 category, u32 access,
                               struct socket *sock)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    if (category == BPFCON_NET_WWW)
        decision = bpfcontain_net_www_perm(container, access);
    else if (category == BPFCON_NET_IPC)
        decision = bpfcontain_net_ipc_perm(container, access, sock);

    return do_policy_decision(container, decision, true);
}

SEC("lsm/socket_create")
int BPF_PROG(socket_create, int family, int type, int protocol, int kern)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_CREATE, NULL);
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(address->sa_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_BIND, sock);
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(address->sa_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_CONNECT, sock);
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_stream_connect, struct socket *sock, struct socket *other,
             struct socket *newsock)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(AF_UNIX);

    return bpfcontain_net_perm(container, category, BPFCON_NET_CONNECT, sock);
}

SEC("lsm/unix_may_send")
int BPF_PROG(unix_may_send, struct socket *sock, struct socket *other)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(AF_UNIX);

    return bpfcontain_net_perm(container, category, BPFCON_NET_SEND, sock);
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_LISTEN, sock);
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_ACCEPT, sock);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_SEND, sock);
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size,
             int flags)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_RECV, sock);
}

SEC("lsm/socket_shutdown")
int BPF_PROG(socket_shutdown, struct socket *sock, int how)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_SHUTDOWN, sock);
}

/* =========================================================================
 * SysV IPC
 * =========================================================================
 */

static int bpfcontain_ipc_perm(container_t *container, container_t *other)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    if (!container && !other) {
        decision = BPFCON_ALLOW;
    } else if (!other) {
        decision = BPFCON_DENY;
    } else {
        decision = check_ipc_access(container, other);
    }

    return do_policy_decision(container, decision, true);
}

SEC("lsm/ipc_permission")
int BPF_PROG(ipc_permission, struct kern_ipc_perm *ipcp, short flag)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    container_t *other = NULL;

    // Look up other container id
    int ipc_id                = ipcp->id;
    u64 *ipc_obj_container_id = bpf_map_lookup_elem(&ipc_handles, &ipc_id);

    // Look up other container
    if (ipc_obj_container_id) {
        other = bpf_map_lookup_elem(&containers, ipc_obj_container_id);
    }

    return bpfcontain_ipc_perm(container, other);
}

SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(msg_queue_alloc_security, struct kern_ipc_perm *ipcp)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int id = ipcp->id;
    bpf_map_update_elem(&ipc_handles, &id, &container->container_id,
                        BPF_NOEXIST);

    return 0;
}

SEC("lsm/msg_queue_free_security")
int BPF_PROG(msg_queue_free_security, struct kern_ipc_perm *ipcp)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int id = ipcp->id;
    bpf_map_delete_elem(&ipc_handles, &id);

    return 0;
}

SEC("lsm/shm_alloc_security")
int BPF_PROG(shm_alloc_security, struct kern_ipc_perm *ipcp)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int id = ipcp->id;
    bpf_map_update_elem(&ipc_handles, &id, &container->container_id,
                        BPF_NOEXIST);

    return 0;
}

SEC("lsm/shm_free_security")
int BPF_PROG(shm_free_security, struct kern_ipc_perm *ipcp)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int id = ipcp->id;
    bpf_map_delete_elem(&ipc_handles, &id);

    return 0;
}

SEC("lsm/sem_alloc_security")
int BPF_PROG(sem_alloc_security, struct kern_ipc_perm *ipcp)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int id = ipcp->id;
    bpf_map_update_elem(&ipc_handles, &id, &container->container_id,
                        BPF_NOEXIST);

    return 0;
}

SEC("lsm/sem_free_security")
int BPF_PROG(sem_free_security, struct kern_ipc_perm *ipcp)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int id = ipcp->id;
    bpf_map_delete_elem(&ipc_handles, &id);

    return 0;
}

/* =========================================================================
 * Signals
 * =========================================================================
 */

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *target, struct kernel_siginfo *info,
             int sig, const struct cred *cred)
{
    // Look up the container using the current PID
    u32 pid                    = bpf_get_current_pid_tgid();
    container_t *container     = get_container_by_host_pid(pid);
    policy_decision_t decision = BPFCON_NO_DECISION;

    // Unconfined
    if (!container)
        return 0;

    // Look up the other container
    // If it's the same one, allow the access
    container_t *other = get_container_by_host_pid(target->pid);
    if (!other) {
        decision |= BPFCON_DENY;
    } else if (container->container_id == other->container_id) {
        decision |= BPFCON_ALLOW;
    } else {
        // TODO: signal policy here
    }

    return do_policy_decision(container, decision, true);
}

/* =========================================================================
 * Capability Policy
 * =========================================================================
 */

/* Convert a POSIX capability into an "access vector".
 *
 * @cap: Requested POSIX capability
 *
 * return: Converted capability.
 */
static __always_inline capability_t cap_to_access(int cap)
{
    switch (cap) {
    case CAP_CHOWN:
        return BPFCON_CAP_CHOWN;
        break;
    case CAP_DAC_OVERRIDE:
        return BPFCON_CAP_DAC_OVERRIDE;
        break;
    case CAP_DAC_READ_SEARCH:
        return BPFCON_CAP_DAC_READ_SEARCH;
        break;
    case CAP_FOWNER:
        return BPFCON_CAP_FOWNER;
        break;
    case CAP_FSETID:
        return BPFCON_CAP_FSETID;
        break;
    case CAP_KILL:
        return BPFCON_CAP_KILL;
        break;
    case CAP_SETGID:
        return BPFCON_CAP_SETGID;
        break;
    case CAP_SETUID:
        return BPFCON_CAP_SETUID;
        break;
    case CAP_SETPCAP:
        return BPFCON_CAP_SETPCAP;
        break;
    case CAP_LINUX_IMMUTABLE:
        return BPFCON_CAP_LINUX_IMMUTABLE;
        break;
    case CAP_NET_BIND_SERVICE:
        return BPFCON_CAP_NET_BIND_SERVICE;
        break;
    case CAP_NET_BROADCAST:
        return BPFCON_CAP_NET_BROADCAST;
        break;
    case CAP_NET_ADMIN:
        return BPFCON_CAP_NET_ADMIN;
        break;
    case CAP_NET_RAW:
        return BPFCON_CAP_NET_RAW;
        break;
    case CAP_IPC_LOCK:
        return BPFCON_CAP_IPC_LOCK;
        break;
    case CAP_IPC_OWNER:
        return BPFCON_CAP_IPC_OWNER;
        break;
    case CAP_SYS_MODULE:
        return BPFCON_CAP_SYS_MODULE;
        break;
    case CAP_SYS_RAWIO:
        return BPFCON_CAP_SYS_RAWIO;
        break;
    case CAP_SYS_CHROOT:
        return BPFCON_CAP_SYS_CHROOT;
        break;
    case CAP_SYS_PTRACE:
        return BPFCON_CAP_SYS_PTRACE;
        break;
    case CAP_SYS_PACCT:
        return BPFCON_CAP_SYS_PACCT;
        break;
    case CAP_SYS_ADMIN:
        return BPFCON_CAP_SYS_ADMIN;
        break;
    case CAP_SYS_BOOT:
        return BPFCON_CAP_SYS_BOOT;
        break;
    case CAP_SYS_NICE:
        return BPFCON_CAP_SYS_NICE;
        break;
    case CAP_SYS_RESOURCE:
        return BPFCON_CAP_SYS_RESOURCE;
        break;
    case CAP_SYS_TIME:
        return BPFCON_CAP_SYS_TIME;
        break;
    case CAP_SYS_TTY_CONFIG:
        return BPFCON_CAP_SYS_TTY_CONFIG;
        break;
    case CAP_MKNOD:
        return BPFCON_CAP_MKNOD;
        break;
    case CAP_LEASE:
        return BPFCON_CAP_LEASE;
        break;
    case CAP_AUDIT_WRITE:
        return BPFCON_CAP_AUDIT_WRITE;
        break;
    case CAP_AUDIT_CONTROL:
        return BPFCON_CAP_AUDIT_CONTROL;
        break;
    case CAP_SETFCAP:
        return BPFCON_CAP_SETFCAP;
        break;
    case CAP_MAC_OVERRIDE:
        return BPFCON_CAP_MAC_OVERRIDE;
        break;
    case CAP_MAC_ADMIN:
        return BPFCON_CAP_MAC_ADMIN;
        break;
    case CAP_SYSLOG:
        return BPFCON_CAP_SYSLOG;
        break;
    case CAP_WAKE_ALARM:
        return BPFCON_CAP_WAKE_ALARM;
        break;
    case CAP_BLOCK_SUSPEND:
        return BPFCON_CAP_BLOCK_SUSPEND;
        break;
    case CAP_AUDIT_READ:
        return BPFCON_CAP_AUDIT_READ;
        break;
    case CAP_PERFMON:
        return BPFCON_CAP_PERFMON;
        break;
    case CAP_BPF:
        return BPFCON_CAP_BPF;
        break;
    case CAP_CHECKPOINT_RESTORE:
        return BPFCON_CAP_CHECKPOINT_RESTORE;
        break;
    default:
        break;
    }

    return 0;
}

/* Restrict policy capabilities */
SEC("lsm/capable")
int BPF_PROG(capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts)
{
    int ret = 0;

    policy_decision_t decision = BPFCON_NO_DECISION;

    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Convert cap to an "access vector"
    // (even though only one bit will be on at a time)
    capability_t access = cap_to_access(cap);
    if (!access) { // Something has gone wrong
        decision = BPFCON_DENY;
        goto out;
    }

    // Capability should be implicitly denied
    if (access & CAP_IMPLICIT_DENY_MASK) {
        decision = BPFCON_DENY;
        goto out;
    }

    cap_policy_key_t key = {};
    key.policy_id        = container->policy_id;

    cap_policy_val_t *val = bpf_map_lookup_elem(&cap_policy, &key);
    // Entire access must match to allow
    if (val && (val->allow & access) == access)
        decision |= BPFCON_ALLOW;
    // Any part of access must match to taint
    if (val && (val->taint & access))
        decision |= BPFCON_TAINT;
    // Any part of access must match to deny
    if (val && (val->deny & access))
        decision |= BPFCON_DENY;

out:
    ret = do_policy_decision(container, decision, true);

    // Submit an audit event
    audit_data_t *event =
        alloc_audit_event(container->policy_id, AUDIT_TYPE_CAP,
                          decision_to_audit_level(decision, true));
    if (event) {
        event->cap.cap = access;
        submit_audit_event(event);
    }

    return ret;
}

/* ========================================================================= *
 * Implicit Policy                                                           *
 * ========================================================================= */

// FIXME: Implement complaining mode for all of the following

/* Disallow BPF */
SEC("lsm/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow misc. dangerous operations */
SEC("lsm/locked_down")
int BPF_PROG(locked_down, enum lockdown_reason what)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
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
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_alloc")
int BPF_PROG(perf_event_alloc, struct perf_event *event)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_read")
int BPF_PROG(perf_event_read, struct perf_event *event)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow perf */
SEC("lsm/perf_event_write")
int BPF_PROG(perf_event_write, struct perf_event *event)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow access to kernel keyring */
SEC("lsm/key_alloc")
int BPF_PROG(key_alloc, int unused)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow access to kernel keyring */
SEC("lsm/key_permission")
int BPF_PROG(key_permission, int unused)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow access to set system time */
SEC("lsm/settime")
int BPF_PROG(settime, int unused)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow ptrace outside of the container */
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    // Look up the container using the current PID
    u32 pid                      = bpf_get_current_pid_tgid();
    container_t *container       = get_container_by_host_pid(pid);
    container_t *child_container = get_container_by_host_pid(child->pid);

    // Unconfined
    if (!container)
        return 0;

    // Parent is unconfined
    if (!child_container)
        return -EACCES;

    // We are in the same container
    if (container->container_id == child_container->container_id)
        return 0;

    return -EACCES;
}

/* Disallow ptrace outside of the container */
SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_traceme, struct task_struct *parent)
{
    // Look up the container using the current PID
    u32 pid                       = bpf_get_current_pid_tgid();
    container_t *container        = get_container_by_host_pid(pid);
    container_t *parent_container = get_container_by_host_pid(parent->pid);

    // Unconfined
    if (!container)
        return 0;

    // Parent is unconfined
    if (!parent_container)
        return -EACCES;

    // We are in the same container
    if (container->container_id == parent_container->container_id)
        return 0;

    return -EACCES;
}

/**
 * lsm/sb_mount - Disallow mounting (for now)
 *
 * @FIXME: Make this work with Docker integration (containerd_shim will need to
 * mount devices before it containerizes, so we either need to consider that
 * here or delay starting BPFContain confinement until all mountpoints have been
 * mounted). Another option is providing a special whitelist of allowed mount
 * paths.
 *
 * @TODO: This hook would be perfect for associating a container with its
 * filesystem mounts (for implicit filesystem policy). We can detect what
 * filesystems it mounts (and determine whether or not they are already mounted
 * by somebody else). If everything looks kosher, we can grant implicit access
 * here (likely by populating some map that tracks this information).
 */
SEC("lsm/sb_mount")
int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* It is punishable by death to attempt to switch namespaces while in
 * a container. */
SEC("fentry/switch_task_namespaces")
int fentry_switch_task_namespaces(struct task_struct *p, struct nsproxy *new)
{
    // Look up the container using the current PID
    u32 pid                = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    bpf_send_signal(SIGKILL);

    return 0;
}

/* It is punishable by death to escalate privileges without going through an
 * execve. */
// FIXME: This seems like a totally flawed approach
// SEC("fentry/commit_creds")
// int fentry_commit_creds(struct cred *new)
//{
//    // Look up the container using the current PID
//    u32 pid = bpf_get_current_pid_tgid();
//    container_t *container = get_container_by_host_pid(pid);
//
//    // Unconfined
//    if (!container)
//        return 0;
//
//    // In a lower namespace
//    long cred_user_ns_addr = (long)BPF_CORE_READ(new, user_ns);
//    bpf_printk("%lx", cred_user_ns_addr);
//    if (cred_user_ns_addr && cred_user_ns_addr != (long)&init_user_ns)
//        return 0;
//
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//
//    u32 old_uid = BPF_CORE_READ(task, real_cred, uid.val);
//    u32 old_gid = BPF_CORE_READ(task, real_cred, gid.val);
//    u32 old_euid = BPF_CORE_READ(task, real_cred, euid.val);
//    u32 old_egid = BPF_CORE_READ(task, real_cred, egid.val);
//
//    u32 new_uid = BPF_CORE_READ(new, uid.val);
//    u32 new_gid = BPF_CORE_READ(new, gid.val);
//    u32 new_euid = BPF_CORE_READ(new, euid.val);
//    u32 new_egid = BPF_CORE_READ(new, egid.val);
//
//    bpf_printk("old_uid = %u new_uid = %u", old_uid, new_uid);
//    bpf_printk("old_gid = %u new_gid = %u", old_gid, new_gid);
//    bpf_printk("old_euid = %u new_euid = %u", old_euid, new_euid);
//    bpf_printk("old_egid = %u new_egid = %u", old_egid, new_egid);
//    bpf_printk("");
//
//    if (old_uid != 0 && new_uid == 0)
//        bpf_send_signal(SIGKILL);
//
//    if (old_gid != 0 && new_gid == 0)
//        bpf_send_signal(SIGKILL);
//
//    if (old_euid != 0 && new_euid == 0)
//        bpf_send_signal(SIGKILL);
//
//    if (old_egid != 0 && new_egid == 0)
//        bpf_send_signal(SIGKILL);
//
//    return 0;
//}

/* ========================================================================= *
 * Bookkeeping                                                               *
 * ========================================================================= */

/* Propagate a process' policy_id to its children */
SEC("tp_btf/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args *args)
{
    struct task_struct *parent = (struct task_struct *)args->args[0];
    struct task_struct *child  = (struct task_struct *)args->args[1];

    // Get container using the parent process, if one exists.
    container_t *container = get_container_by_host_pid(parent->pid);
    if (!container)
        return 0;

    u64 pid_tgid = (u64)child->tgid << 32 | child->pid;

    // Add the new process to the container
    process_t *process = add_process_to_container(container, pid_tgid,
                                                  get_task_ns_pid_tgid(child));
    if (!process) {
        // TODO log error
    }

    return 0;
}

/* Propagate a process' policy_id to its children */
SEC("tp_btf/sched_process_exit")
int sched_process_exit(struct bpf_raw_tracepoint_args *args)
{
    struct task_struct *task = (struct task_struct *)args->args[0];

    // Get container using the parent process, if one exists.
    container_t *container = get_container_by_host_pid(task->pid);
    if (!container)
        return 0;

    remove_process_from_container(container, task->pid);

    return 0;
}

/* ========================================================================= *
 * Uprobe Commands                                                           *
 * ========================================================================= */

/* BPF program endpoint for do_containerize in libbpfcontain.
 *
 * @ret_p: Pointer to the return value of wrapper function.
 * @policy_id: Container with which to associate.
 *
 * return: Converted access mask.
 */
SEC("uprobe/do_containerize")
int BPF_KPROBE(do_containerize, int *ret_p, u64 policy_id)
{
    int ret = 0;

    // Look up common policy information from policy_common map
    policy_common_t *common = bpf_map_lookup_elem(&policy_common, &policy_id);
    if (!common) {
        ret = -ENOENT;
        goto out;
    }

    // Try to add a process to `processes` with `pid`/`tgid`, associated with
    // `policy_id`
    if (!start_container(policy_id, common->default_taint)) {
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
