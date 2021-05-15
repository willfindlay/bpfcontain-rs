// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "maps.h"
#include "state.h"

#define ALLOCATOR(TYPE)                                                        \
    BPF_PERCPU_ARRAY(__##TYPE##__alloc, TYPE, 1, 0,                            \
                     BPF_F_RDONLY | BPF_F_RDONLY_PROG);                        \
    BPF_PERCPU_ARRAY(__##TYPE##__temp, TYPE, 1, 0, BPF_F_RDONLY);              \
                                                                               \
    static __always_inline TYPE *new_##TYPE()                                  \
    {                                                                          \
        int zero = 0;                                                          \
                                                                               \
        TYPE *temp = bpf_map_lookup_elem(&__##TYPE##__alloc, &zero);           \
        if (!temp)                                                             \
            return NULL;                                                       \
                                                                               \
        bpf_map_update_elem(&__##TYPE##__temp, &zero, temp, 0);                \
        return bpf_map_lookup_elem(&__##TYPE##__temp, &zero);                  \
    }

ALLOCATOR(container_t);
ALLOCATOR(process_t);

#endif /* ifndef ALLOCATOR_H */
