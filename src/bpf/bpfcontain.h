// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#ifndef PROGS_BPF_H
#define PROGS_BPF_H

// This must be first
#include "vmlinux.h"

// These must be below vmlinux.h
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

#include "../include/structs.h"
#include "kernel_defs.h"
#include "maps.h"

#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))

#define BPFCON_MAX_CONTAINERS 10240
#define BPFCON_MAX_PROCESSES  10240
#define BPFCON_MAX_POLICY     10240

#endif /* ifndef PROGS_BPF_H */

