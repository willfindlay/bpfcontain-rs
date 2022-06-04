// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_PROCESS_SHARED_H
#define BPFCONTAIN_PROCESS_SHARED_H

#include "vmlinux.h"

#include "defs.h"

/**
 * A unique identifier representing a BPFContain policy.
 */
typedef u64 policy_id_t;

/**
 * A unique identifier backing a BPFContain container.
 */
typedef u64 container_id_t;

/**
 * Represents per-task metadata.
 */
typedef struct {
	// id of the container this process belongs to
    container_id_t container_id;
	// pid (userspace tid) of the process in the host pid namespace
    u32 host_pid;
	// thread group id (userspace pid)  of the process in the host pid namespace
    u32 host_tgid;
	// pid (userspace tid) of the process in its own pid namespace
    u32 pid;
	// thread group id (userspace pid)  of the process in its own pid namespace
    u32 tgid;
} process_t;

#endif /* ifndef BPFCONTAIN_PROCESS_SHARED_H */
