// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef DEFS_H
#define DEFS_H

#define BPFCON_MAX_CONTAINERS 10240
// TODO: This will no longer be necessary with task_local_storage in 5.11
#define BPFCON_MAX_PROCESSES 10240
#define BPFCON_MAX_POLICY 10240

#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))

#define __PACKED __attribute__((__packed__))

#endif /* ifndef DEFS_H */
