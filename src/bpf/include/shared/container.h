// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_CONTAINER_SHARED_H
#define BPFCONTAIN_CONTAINER_SHARED_H

#include "vmlinux.h"

#include "defs.h"
#include "process.h"

/**
 * Represents the state of a container.
 */
typedef enum {
	// The built-in shim doesn't track state currently
    DEFAULT_SHIM = 0,
	// Runc has started creating a new container
    DOCKER_INIT = 1000,
	// Dockerd has reported that the container setup is finished
    DOCKER_STARTED = 1001,
} container_status_t;

/**
 * Represents per-container metadata.
 */
typedef struct {
    // ID of bpfcontain policy associated with this container
    policy_id_t policy_id;
    // BPFContain's version of a container id,
    // also used as a key into the map of containers
    container_id_t container_id;
    // The mount namespace id of this container
    u32 mnt_ns_id;
    // The pid namespace id of this container
    u32 pid_ns_id;
    // The user namespace id of this container
    u32 user_ns_id;
    // Reference count of the container (how many tasks are running inside it)
    // this should only be incremented and decremented atomically
    u32 refcount;
    // Is the container in a tainted state?
    u8 tainted : 1;
    // Is the container in complain mode?
    u8 complain : 1;
    // Is the container in privileged mode?
    u8 privileged : 1;
    // Often corresponds with container id on the docker side
    char uts_name[16];
    // Tracks the state of a container
    container_status_t status;
} container_t;

#endif /* ifndef BPFCONTAIN_CONTAINER_SHARED_H */
