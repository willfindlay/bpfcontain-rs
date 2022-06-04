// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_POLICY_SHARED_H
#define BPFCONTAIN_POLICY_SHARED_H

#include "vmlinux.h"

#include "defs.h"

/**
 * Represents a BPFcontain policy decision.
 */
typedef enum {
	// No policy decision
    BPFCON_NO_DECISION = 0U,
	// Allow access
    BPFCON_ALLOW       = (1U << 0),
	// Deny access
    BPFCON_DENY        = (1U << 1),
	// Taint the container
    BPFCON_TAINT       = (1U << 2),
} policy_decision_t;

/**
 * The common part of a BPFContain policy.
 * @default_taint: S
 * @complain: Should containers under this policy spawn in complaining mode?
 */
typedef struct {
	// Should containers under this policy spawn tainted?
    u8 default_taint : 1;
	// Should containers under this policy spawn in complaining mode?
    u8 complain : 1;
	// Should containers under this policy spawn in privileged mode?
    u8 privileged : 1;
} __PACKED policy_common_t;

#endif /* ifndef BPFCONTAIN_POLICY_SHARED_H */
