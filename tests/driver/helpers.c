// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "helpers.h"

void print_usage()
{
    fprintf(stderr, "USAGE: driver <TEST_CASE> [ARGS ...]\n");
    exit(-1);
}

void print_error(char *s)
{
    fprintf(stderr, "ERROR: %s\n", s);
    exit(-1);
}
