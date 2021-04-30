// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Apr. 30, 2021  William Findlay  Created this.
//
// A simple driver program for policy enforcement integration tests.

#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "helpers.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage();
    }

    // Dispatch into distinct test cases
    if (!strcmp(argv[1], "open1")) {
    }

    return 0;
}
