// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include "libbpfcontain.h"

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

static void do_containerize(int *ret, unsigned long container_id)
{
}

int containerize(unsigned long container_id)
{
    int ret = -EAGAIN;

    do_containerize(&ret, container_id);

    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return 0;
}
