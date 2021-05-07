// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef STATE_H
#define STATE_H

#include "user_types.h"

// TODO: use this wherever we have a policy id or a container id
typedef u64 policy_id_t;
typedef u64 container_id_t;

typedef struct {
    container_id_t container_id;
    u32 host_pid;
    u32 host_tgid;
    u32 pid;
    u32 tgid;
} process_t;

// Represents the state of a container
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
    // often corresponds with container id on the docker side
    char uts_name[16];
} container_t;

#endif /* ifndef STATE_H */
