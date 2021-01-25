// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include "bpfcontain.h"

/* ========================================================================= *
 * Structs Not Included in vmlinux.h                                         *
 * ========================================================================= */

/* Needed for overlayfs support, TODO: sync with Linux version */
struct ovl_inode {
    union {
        struct ovl_dir_cache *cache; /* directory */
        struct inode *lowerdata;     /* regular file */
    };
    const char *redirect;
    u64 version;
    unsigned long flags;
    struct inode vfs_inode;
    struct dentry *__upperdentry;
    struct inode *lower;

    /* synchronize copy up and more */
    struct mutex lock;
};

/* ========================================================================= *
 * BPF CO-RE Globals                                                         *
 * ========================================================================= */

// Settings
// TODO: change this to audit_level_t when we add
// support for enums in libbpf-rs
u32 audit_level = DEFAULT_AUDIT_LEVEL;

// Constants
const volatile u32 bpfcontain_pid;
const volatile u32 host_mnt_ns_id;
const volatile u32 host_pid_ns_id;

/* ========================================================================= *
 * Allocator Maps                                                            *
 * ========================================================================= */

#define ALLOCATOR(TYPE)                                              \
    BPF_PERCPU_ARRAY(__##TYPE##__alloc, TYPE, 1,                     \
                     BPF_F_RDONLY | BPF_F_RDONLY_PROG);              \
    BPF_PERCPU_ARRAY(__##TYPE##__temp, TYPE, 1, BPF_F_RDONLY);       \
                                                                     \
    static __always_inline TYPE *new_##TYPE()                        \
    {                                                                \
        int zero = 0;                                                \
                                                                     \
        TYPE *temp = bpf_map_lookup_elem(&__##TYPE##__alloc, &zero); \
        if (!temp)                                                   \
            return NULL;                                             \
                                                                     \
        bpf_map_update_elem(&__##TYPE##__temp, &zero, temp, 0);      \
        return bpf_map_lookup_elem(&__##TYPE##__temp, &zero);        \
    }

ALLOCATOR(container_t);
ALLOCATOR(process_t);

/* =========================================================================
 * BPF Maps
 * ========================================================================= */

/* Ring buffer for passing logging events to userspace */
BPF_RINGBUF(audit_file_buf, 4);
BPF_RINGBUF(audit_cap_buf, 4);
BPF_RINGBUF(audit_net_buf, 4);
BPF_RINGBUF(audit_ipc_buf, 4);

/* Active (containerized) processes */
BPF_LRU_HASH(processes, u32, process_t, BPFCON_MAX_PROCESSES, 0);
BPF_LRU_HASH(containers, container_id_t, container_t, BPFCON_MAX_CONTAINERS, 0);

/* Files and directories which have been created by a containerized process */
BPF_INODE_STORAGE(task_inodes, container_id_t, 0);

/* Active policy */
BPF_HASH(policies, u64, policy_t, BPFCON_MAX_CONTAINERS, 0);

/* Filesystem policy */
BPF_HASH(fs_allow, fs_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(fs_deny, fs_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(fs_taint, fs_policy_key_t, u32, BPFCON_MAX_POLICY, 0);

/* File policy */
BPF_HASH(file_allow, file_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(file_deny, file_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(file_taint, file_policy_key_t, u32, BPFCON_MAX_POLICY, 0);

/* Device policy */
BPF_HASH(dev_allow, dev_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(dev_deny, dev_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(dev_taint, dev_policy_key_t, u32, BPFCON_MAX_POLICY, 0);

/* Capability policy */
BPF_HASH(cap_allow, cap_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(cap_deny, cap_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(cap_taint, cap_policy_key_t, u32, BPFCON_MAX_POLICY, 0);

/* Network policy */
BPF_HASH(net_allow, net_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(net_deny, net_policy_key_t, u32, BPFCON_MAX_POLICY, 0);
BPF_HASH(net_taint, net_policy_key_t, u32, BPFCON_MAX_POLICY, 0);

/* IPC policy */
BPF_HASH(ipc_allow, ipc_policy_key_t, u64, BPFCON_MAX_POLICY, 0);
BPF_HASH(ipc_deny, ipc_policy_key_t, u64, BPFCON_MAX_POLICY, 0);
BPF_HASH(ipc_taint, ipc_policy_key_t, u64, BPFCON_MAX_POLICY, 0);

/* ========================================================================= *
 * Audit Helpers                                                             *
 * ========================================================================= */

static __always_inline bool __should_audit(policy_decision_t decision)
{
    if (decision & BPFCON_DENY && audit_level & BC_AUDIT_DENY)
        return true;

    else if (decision & BPFCON_TAINT && audit_level & BC_AUDIT_TAINT)
        return true;

    else if (decision & BPFCON_ALLOW && audit_level & BC_AUDIT_ALLOW)
        return true;

    return false;
}

static __always_inline void
__do_audit_common(audit_common_t *common, policy_decision_t decision,
                  u64 policy_id)
{
    common->decision = decision;
    common->policy_id = policy_id;
    common->pid = bpf_get_current_pid_tgid();
    common->tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(common->comm, sizeof(common->comm));
}

/* Log a filesystem policy event to userspace.
 *
 * @decision: The policy decision.
 * @policy_id: Current policy ID.
 * @inode: A pointer to the inode in question.
 * @access: The requested access.
 */
static __always_inline void
audit_inode(policy_decision_t decision, u64 policy_id, bool tainted,
            struct inode *inode, file_permission_t access)
{
    if (tainted && !(decision & BPFCON_ALLOW))
        decision |= BPFCON_DENY;

    if (!__should_audit(decision))
        return;

    // Reserve space for the event on the ring buffer
    audit_file_t *event =
        bpf_ringbuf_reserve(&audit_file_buf, sizeof(audit_file_t), 0);

    if (!event)
        return;

    __do_audit_common(&event->common, decision, policy_id);

    event->access = access;
    event->st_ino = inode->i_ino;
    event->st_dev = new_encode_dev(inode->i_sb->s_dev);

    // Submit the event
    bpf_ringbuf_submit(event, 0);
}

/* Log a capability policy event to userspace.
 *
 * @decision: The policy decision.
 * @policy_id: Current policy ID.
 * @cap: The requested capability.
 */
static __always_inline void audit_cap(policy_decision_t decision, u64 policy_id,
                                      bool tainted, capability_t cap)
{
    if (tainted && !(decision & BPFCON_ALLOW))
        decision |= BPFCON_DENY;

    if (!__should_audit(decision))
        return;

    // Reserve space for the event on the ring buffer
    audit_cap_t *event =
        bpf_ringbuf_reserve(&audit_cap_buf, sizeof(audit_cap_t), 0);

    if (!event)
        return;

    __do_audit_common(&event->common, decision, policy_id);

    event->cap = cap;

    // Submit the event
    bpf_ringbuf_submit(event, 0);
}

/* Log a network policy event to userspace.
 *
 * @decision: The policy decision.
 * @policy_id: Current policy ID.
 * @operation: The requested socket operation.
 */
static __always_inline void audit_net(policy_decision_t decision, u64 policy_id,
                                      bool tainted, net_operation_t operation)
{
    if (tainted && !(decision & BPFCON_ALLOW))
        decision |= BPFCON_DENY;

    if (!__should_audit(decision))
        return;

    // Reserve space for the event on the ring buffer
    audit_net_t *event =
        bpf_ringbuf_reserve(&audit_net_buf, sizeof(audit_net_t), 0);

    if (!event)
        return;

    __do_audit_common(&event->common, decision, policy_id);

    event->operation = operation;

    // Submit the event
    bpf_ringbuf_submit(event, 0);
}

/* Log an ipc policy event to userspace.
 *
 * @decision: The policy decision.
 * @policy_id: Current policy ID.
 * @other_policy_id: The policy ID of the other container.
 * @sender: 1 if we are the current sender, 0 otherwise
 */
static __always_inline void
audit_ipc(policy_decision_t decision, u64 policy_id, bool tainted,
          u64 other_policy_id, u8 sender)
{
    if (tainted && !(decision & BPFCON_ALLOW))
        decision |= BPFCON_DENY;

    if (!__should_audit(decision))
        return;

    // Reserve space for the event on the ring buffer
    audit_ipc_t *event =
        bpf_ringbuf_reserve(&audit_ipc_buf, sizeof(audit_ipc_t), 0);

    if (!event)
        return;

    __do_audit_common(&event->common, decision, policy_id);

    event->other_policy_id = other_policy_id;
    event->sender = sender;

    // Submit the event
    bpf_ringbuf_submit(event, 0);
}

/* ========================================================================= *
 * Helpers                                                                   *
 * ========================================================================= */

/* Get the policy with ID @policy_id.
 *
 * TODO: call this instead wherever we get the current policy
 *
 * @policy_id: Container ID to lookup.
 *
 * return: Pointer to the policy.
 */
static __always_inline policy_t *get_policy(u64 policy_id)
{
    policy_t *policy = bpf_map_lookup_elem(&policies, &policy_id);
    // if (!policy)
    //    log_event(ET_NO_SUCH_CONTAINER, EA_ERROR, policy_id);

    return policy;
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
    unsigned long flags = BPF_CORE_READ(inode, i_sb, s_flags);
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

    // FIXME: not working
    if (access & MAY_CHDIR) {
        access |= BPFCON_MAY_CHDIR;
    }

    // Ignore execute permissions on directories, since we already caught
    // MAY_CHDIR
    if (!S_ISDIR(BPF_CORE_READ(inode, i_mode)) && (mask & MAY_EXEC)) {
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

    ipc_policy_key_t key = {};

    key.policy_id = container->policy_id;
    key.other_policy_id = other_container->policy_id;

    ipc_policy_key_t other_key = {};

    key.policy_id = other_container->policy_id;
    key.other_policy_id = container->policy_id;

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
 * return: Converted access mask.
 */
static __always_inline int
do_policy_decision(container_t *container, policy_decision_t decision,
                   u8 ignore_taint)
{
    u8 tainted = container->tainted || ignore_taint;

    // Taint container
    if (decision & BPFCON_TAINT) {
        container->tainted = 1;
    }

    // Always deny if denied
    if (decision & BPFCON_DENY) {
        return -EACCES;
    }

    // Always allow if allowed and not denied
    if (decision & BPFCON_ALLOW) {
        return 0;
    }

    policy_t *policy = bpf_map_lookup_elem(&policies, &container->policy_id);
    // Something went wrong, assume default deny
    if (!policy) {
        return -EACCES;
    }

    // If tainted and default-deny with no policy decision, deny
    if (tainted && policy->default_deny) {
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
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

/* Get the pid namespace id for the current task.
 *
 * return: Pid namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_pid_ns_id()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

/* Get the uts namespace name for the current task. */
static __always_inline void get_current_uts_name(char *dest, size_t size)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char *uts_name = BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename);
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
    struct vfsmount *vfsmnt = BPF_CORE_READ(file, f_path.mnt);
    if (!vfsmnt)
        return 0;

    struct mount *mnt = get_real_mount(vfsmnt);
    if (!mnt)
        return 0;

    return BPF_CORE_READ(mnt, mnt_ns, ns.inum);
}

/* Get the mount namespace id for @path.
 *
 * @path: Pointer to a path struct.
 *
 * return: Mount namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_path_mnt_ns_id(const struct path *path)
{
    struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    if (!vfsmnt)
        return 0;

    struct mount *mnt = get_real_mount(vfsmnt);
    if (!mnt)
        return 0;

    return BPF_CORE_READ(mnt, mnt_ns, ns.inum);
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
    u32 level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
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
    u32 level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
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
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
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
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
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
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return get_task_ns_pid_tgid(task);
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
static __always_inline bool
filter_inode_by_magic(struct inode *inode, u64 magic)
{
    u64 inode_magic = BPF_CORE_READ(inode, i_sb, s_magic);

    if (inode_magic == magic)
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
static __always_inline void
add_inode_to_container(const container_t *container, struct inode *inode)
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
static __always_inline process_t *
add_process_to_container(container_t *container, u64 host_pid_tgid,
                         u64 pid_tgid)
{
    // Null check on container
    if (!container)
        return NULL;

    // Allocate a new process
    process_t *process = new_process_t();
    if (!process)
        return NULL;

    process->container_id = container->container_id;
    process->host_pid = host_pid_tgid;
    process->host_tgid = (host_pid_tgid >> 32);
    process->pid = pid_tgid;
    process->tgid = (pid_tgid >> 32);

    bpf_printk("child pid is %u", process->host_pid);

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

/* Start a new container.
 *
 * Params:
 *    @policy_id: The policy id to associated with the container
 *
 * Returns:
 *    A pointer to the newly created container, if successful
 *    Otherwise, NULL
 */
static __always_inline container_t *
start_container(policy_id_t policy_id, bool tainted)
{
    // Allocate a new container
    container_t *container = new_container_t();
    if (!container)
        return NULL;

    u32 pid = bpf_get_current_pid_tgid();

    // Initialize the container
    // The container id is a 64 bit integer where the upper 32 bits are a random
    // integer and the lower 32 bits are the _host_ pid of the initial process.
    container->container_id = ((u64)bpf_get_prandom_u32() << 32 | pid);
    // The mount ns id of the container
    container->mnt_ns_id = get_current_mnt_ns_id();
    // The pid ns id of the container
    container->pid_ns_id = get_current_pid_ns_id();
    // The id of the bpfcontain policy that should be associated with the
    // container
    container->policy_id = policy_id;
    // The container's refcount. Starts at 1 to accomodate the initial process
    container->refcount = 0;
    // Is the container tainted?
    container->tainted = tainted;
    // The UTS namespace hostname of the container. In docker and kubernetes,
    // this usually corresponds with their notion of a container id.
    get_current_uts_name(container->uts_name, sizeof(container->uts_name));

    // In a different PID ns:
    if (get_current_ns_pid() == 1) {
        // TODO
    }

    if (!add_process_to_container(container, bpf_get_current_pid_tgid(),
                                  get_current_ns_pid_tgid())) {
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
static __always_inline int
do_fs_permission(container_t *container, struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;

    fs_policy_key_t key = {};

    key.policy_id = container->policy_id;
    key.device_id = new_encode_dev(BPF_CORE_READ(inode, i_sb, s_dev));

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
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static __always_inline int
do_file_permission(container_t *container, struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;

    file_policy_key_t key = {};

    key.policy_id = container->policy_id;
    key.device_id = new_encode_dev(BPF_CORE_READ(inode, i_sb, s_dev));
    key.inode_id = BPF_CORE_READ(inode, i_ino);

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
 * @policy_id: 64-bit id of the current policy
 * @inode: A pointer to the inode being accessed
 * @access: BPFContain access mask
 *
 * return: A BPFContain decision
 */
static __always_inline int
do_dev_permission(container_t *container, struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;

    dev_policy_key_t key = {};

    // Look up policy by device major number and policy ID
    key.policy_id = container->policy_id;
    key.major = MAJOR(BPF_CORE_READ(inode, i_rdev));

    // Not a device driver
    if (!key.major) {
        return BPFCON_NO_DECISION;
    }

    /*
     * Try with minor = -1 first (wildcard)
     */
    key.minor = MINOR_WILDCARD;

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

    /*
     * Try with minor = i_rdev's minor second
     */
    key.minor = MINOR(BPF_CORE_READ(inode, i_rdev));

    // If we are allowing the _entire_ access, allow
    allowed = bpf_map_lookup_elem(&dev_allow, &key);
    if (allowed && ((*allowed & access) == access)) {
        decision |= BPFCON_ALLOW;
    }

    // If we are denying _any part_ of the access, deny
    denied = bpf_map_lookup_elem(&dev_deny, &key);
    if (denied && (*denied & access)) {
        decision |= BPFCON_DENY;
    }

    // If we are tainting _any part_ of the access, taint
    tainted = bpf_map_lookup_elem(&dev_taint, &key);
    if (tainted && (*tainted & access)) {
        decision |= BPFCON_TAINT;
    }

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
static __always_inline int
do_procfs_permission(container_t *container, struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;

    if (!inode)
        return BPFCON_NO_DECISION;

    // Not in procfs
    if (!filter_inode_by_magic(inode, PROC_SUPER_MAGIC))
        return BPFCON_NO_DECISION;

    u32 pid = get_proc_pid(inode);
    if (!pid)
        return BPFCON_NO_DECISION;

    // Does it belong to our policy?
    container_t *inode_container = get_container_by_host_pid(pid);
    if (inode_container &&
        inode_container->container_id == container->container_id) {
        // Apply PROC_INODE_PERM_MASK for implicit privileges
        if ((access & PROC_INODE_PERM_MASK) == access)
            decision |= BPFCON_ALLOW;
    } else {
        decision |= BPFCON_DENY;
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
static __always_inline int
do_overlayfs_permission(container_t *container, struct inode *inode, u32 access)
{
    int decision = BPFCON_NO_DECISION;

    if (!inode)
        return BPFCON_NO_DECISION;

    // Not in an overlayfs
    if (!filter_inode_by_magic(inode, OVERLAYFS_SUPER_MAGIC))
        return BPFCON_NO_DECISION;

    // Is this _our_ overlayfs?
    // TODO

    return decision;
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
static __always_inline int
do_task_inode_permission(container_t *container, struct inode *inode,
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
static int
bpfcontain_inode_perm(container_t *container, struct inode *inode, u32 access)
{
    bool super_allow = false;
    int ret = 0;
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
    if (filter_inode_by_magic(inode, OVERLAYFS_SUPER_MAGIC)) {
        // struct ovl_inode *ovl_inode = get_overlayfs_inode(inode);
        // bpf_printk("ovl inode address %lx", ovl_inode);
    }

    // per-file allow should override per filesystem deny
    decision |= do_procfs_permission(container, inode, access);
    decision |= do_task_inode_permission(container, inode, access);
    decision |= do_file_permission(container, inode, access);
    decision |= do_dev_permission(container, inode, access);

    // per-file allow should override per filesystem deny
    if ((decision & BPFCON_ALLOW) && !(decision & BPFCON_DENY))
        super_allow = true;

    // filesystem-level permissions
    decision |= do_fs_permission(container, inode, access);
    decision |= do_overlayfs_permission(container, inode, access);

    // per-file allow should override per filesystem deny
    if (super_allow)
        decision &= (~BPFCON_DENY);

    ret = do_policy_decision(container, decision, 0);
    audit_inode(decision, container->policy_id, container->tainted, inode,
                access);

    return ret;
}

SEC("lsm/inode_init_security")
int BPF_PROG(inode_init_security, struct inode *inode, struct inode *dir,
             const struct qstr *qstr, const char **name, void **value,
             size_t *len)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Add the newly created inode to the container's list of inodes.
    // This will then be used as a sensible default when computing permissions.
    add_inode_to_container(container, inode);

    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Make an access control decision
    return bpfcontain_inode_perm(container, file->f_inode,
                                 mask_to_access(file->f_inode, mask));
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    // FIXME: temporary
    if (filter_inode_by_magic(file->f_inode, OVERLAYFS_SUPER_MAGIC)) {
        bpf_printk("Hello overlayfs world");
        bpf_printk("file mnt ns is %lu", get_file_mnt_ns_id(file));
    }

    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Make an access control decision
    return bpfcontain_inode_perm(container, file->f_inode,
                                 file_to_access(file));
}

SEC("lsm/file_receive")
int BPF_PROG(file_receive, struct file *file)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
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

    // FIXME: temporary
    if (get_current_ns_pid() == 1) {
        start_container(42, 0);
    }

    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u32 mnt_ns = get_path_mnt_ns_id(dir);
    return bpfcontain_inode_perm(container, dentry->d_inode, BPFCON_MAY_DELETE);
}

/* Mediate access to unlink a directory. */
SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u32 mnt_ns = get_path_mnt_ns_id(dir);
    return bpfcontain_inode_perm(container, dentry->d_inode, BPFCON_MAY_DELETE);
}

/* Mediate access to create a file. */
SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    int ret = bpfcontain_inode_perm(container, dir->dentry->d_inode,
                                    BPFCON_MAY_CREATE);
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
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, dir->dentry->d_inode,
                                 BPFCON_MAY_CREATE);
}

/* Mediate access to make a symlink. */
SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, dir->dentry->d_inode,
                                 BPFCON_MAY_CREATE);
}

/* Mediate access to make a hard link. */
SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    int ret = 0;

    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    ret = bpfcontain_inode_perm(container, new_dir->dentry->d_inode,
                                BPFCON_MAY_CREATE);
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
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    struct inode *old_dir_inode = old_dir->dentry->d_inode;
    struct inode *old_inode = old_dentry->d_inode;
    struct inode *new_dir_inode = new_dir->dentry->d_inode;
    struct inode *new_inode = new_dentry->d_inode;

    ret = bpfcontain_inode_perm(container, old_inode, BPFCON_MAY_RENAME);
    if (ret)
        return ret;

    ret = bpfcontain_inode_perm(container, new_dir_inode, BPFCON_MAY_CREATE);
    if (ret)
        return ret;

    return 0;
}

/* Mediate access to truncate a file. */
SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, const struct path *path)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return bpfcontain_inode_perm(container, path->dentry->d_inode,
                                 BPFCON_MAY_WRITE | BPFCON_MAY_SETATTR);
}

/* Mediate access to chmod a file. */
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
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
static __always_inline int
mmap_permission(container_t *container, struct file *file, unsigned long prot,
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

    return bpfcontain_inode_perm(container, file->f_inode, access);
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return mmap_permission(container, vma->vm_file, prot,
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
bpfcontain_net_www_perm(container_t *container, u32 access)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    net_policy_key_t key = {};

    key.policy_id = container->policy_id;

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

    audit_net(decision, container->policy_id, container->tainted, access);

    return decision;
}

static policy_decision_t
bpfcontain_net_ipc_perm(container_t *container, u32 access, struct socket *sock)
{
    policy_decision_t decision = BPFCON_NO_DECISION;

    u32 other_pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);

    container_t *other_container = get_container_by_host_pid(other_pid);
    if (other_container) {
        decision |= check_ipc_access(container, other_container);
    } else {
        // TODO: handle no other container
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

    return do_policy_decision(container, decision, 0);
}

SEC("lsm/socket_create")
int BPF_PROG(socket_create, int family, int type, int protocol, int kern)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);

    return bpfcontain_net_perm(container, category, BPFCON_NET_SHUTDOWN, sock);
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

/* Restrict policy capabilities */
SEC("lsm/capable")
int BPF_PROG(capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts)
{
    int ret = 0;

    policy_decision_t decision = BPFCON_NO_DECISION;

    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // Convert cap to an "access vector"
    // (even though only one bit will be on at a time)
    u32 access = cap_to_access(cap);
    if (!access) {  // One of our implicit-deny capbilities
        decision = BPFCON_DENY;
        goto out;
    }

    cap_policy_key_t key = {};

    key.policy_id = container->policy_id;

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

out:
    ret = do_policy_decision(container, decision, 1);
    audit_cap(decision, container->policy_id, container->tainted, access);

    return ret;
}

/* ========================================================================= *
 * Implicit Policy                                                           *
 * ========================================================================= */

/* Disallow BPF */
SEC("lsm/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
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
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow ptrace */
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    return -EACCES;
}

/* Disallow ptrace */
// SEC("lsm/ptrace_traceme")
// int BPF_PROG(ptrace_traceme, int unused)
//{
//  // Look up the container using the current PID
//  u32 pid = bpf_get_current_pid_tgid();
//  container_t *container = get_container_by_host_pid(pid);
//
//  // Unconfined
//  if (!container)
//      return 0;
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
    // Look up the container using the current PID
    u32 pid = bpf_get_current_pid_tgid();
    container_t *container = get_container_by_host_pid(pid);

    // Unconfined
    if (!container)
        return 0;

    // TODO: make this work without checking for in_execve, since we want to
    // remove that field from process_t
    // Check to see if the process is in the middle of an execve
    // if (process->in_execve)
    //    return 0;

    // FIXME: find some better logic to gate this, right now it is killing all
    // SUID binaries
    // bpf_send_signal(SIGKILL);

    return 0;
}

/* ========================================================================= *
 * Bookkeeping                                                               *
 * ========================================================================= */

/* Turn on in_execve bit when we are committing credentials */
// SEC("lsm/bprm_committing_creds")
// int BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm)
//{
//    int ret = 0;
//
//    // Look up the process using the current PID
//    u32 pid = bpf_get_current_pid_tgid();
//    process_t *process = bpf_map_lookup_elem(&processes, &pid);
//
//    // Unconfined
//    if (!process)
//        return 0;
//
//    process->in_execve = 1;
//
//    return 0;
//}

/* Turn off in_execve bit when we are done committing credentials */
// SEC("lsm/bprm_committed_creds")
// int BPF_PROG(bprm_committed_creds, struct linux_binprm *bprm)
//{
//    int ret = 0;
//
//    // Look up the process using the current PID
//    u32 pid = bpf_get_current_pid_tgid();
//    process_t *process = bpf_map_lookup_elem(&processes, &pid);
//
//    // Unconfined
//    if (!process)
//        return 0;
//
//    process->in_execve = 0;
//
//    return 0;
//}

/* Propagate a process' policy_id to its children */
SEC("tp_btf/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args *args)
{
    struct task_struct *parent = (struct task_struct *)args->args[0];
    struct task_struct *child = (struct task_struct *)args->args[1];

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

/* ========================================================================= *
 * Filesystem Mounts                                                         *
 * ========================================================================= */

/* TODO: Updating the mnt_ns_active_fs map makes sense here, but we need to
 * figure out how we are going to delete afterwards. Otherwise, incorrect data
 * will carry between containers as namespace ids / device ids are re-used by
 * the kernel. */
// SEC("lsm/sb_set_mnt_opts")
// int BPF_PROG(sb_set_mnt_opts, struct super_block *sb, void *mnt_opts,
//             unsigned long kern_flags, unsigned long *set_kern_flags)
//{
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//    // struct file_system_type *type = sb->s_type;
//
//    struct mnt_ns_fs key = {};
//
//    key.device_id = new_encode_dev(sb->s_dev);
//    key.mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
//
//    if (!key.mnt_ns) {
//        return 0;
//    }
//
//    bpf_printk("alloc mount ns");
//    bpf_printk("dev_id = %lu", key.device_id);
//    bpf_printk("mnt_ns = %u", key.mnt_ns);
//    bpf_printk("   pid = %u\n", (u32)bpf_get_current_pid_tgid());
//
//    u8 val = 1;
//    bpf_map_update_elem(&mnt_ns_active_fs, &key, &val, 0);
//
//    return 0;
//}
//
// SEC("lsm/sb_free_security")
// int BPF_PROG(sb_free_security, struct super_block *sb)
//{
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//
//    struct mnt_ns_fs key = {};
//
//    key.device_id = new_encode_dev(sb->s_dev);
//    key.mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
//
//    bpf_printk("free mount ns");
//    bpf_printk("dev_id = %lu", key.device_id);
//    bpf_printk("mnt_ns = %u", key.mnt_ns);
//    bpf_printk("   pid = %u\n", (u32)bpf_get_current_pid_tgid());
//
//    if (!key.mnt_ns) {
//        return 0;
//    }
//
//    u8 val = 1;
//    bpf_map_delete_elem(&mnt_ns_active_fs, &key);
//
//    return 0;
//}

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
 * @policy_id: Container with which to associate.
 *
 * return: Converted access mask.
 */
SEC("uprobe/do_containerize")
int BPF_KPROBE(do_containerize, int *ret_p, u64 policy_id)
{
    int ret = 0;

    // Look up the `policy` using `policy_id`
    policy_t *policy = bpf_map_lookup_elem(&policies, &policy_id);

    // If the policy doesn't exist, report an error and bail
    if (!policy) {
        ret = -ENOENT;
        goto out;
    }

    // Try to add a process to `processes` with `pid`/`tgid`, associated with
    // `policy_id`
    if (!start_container(policy_id, policy->default_taint)) {
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
