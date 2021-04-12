// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include "../include/libbpfcontain.h"

#include <errno.h>

/* ========================================================================= *
 * Commands                                                                  *
 * ========================================================================= */

/* Commands should always be declared as follows:
 *
 *    void do_COMMAND(int *ret, ...) { }
 *
 *    int COMMAND(...)
 *    {
 *        int ret = -EAGAIN;
 *
 *        do_start_container(&ret, ...);
 *
 *        if (ret < 0) {
 *            errno = ret;
 *        }
 *
 *        return ret;
 *    }
 *
 */

static void do_containerize(int *ret, u64 policy_id, u8 tainted)
{
}

int containerize(u64 policy_id, u8 tainted)
{
    int ret = -EAGAIN;

    do_containerize(&ret, policy_id, tainted);

    if (ret < 0) {
        errno = -ret;
        return ret;
    }

    return 0;
}
