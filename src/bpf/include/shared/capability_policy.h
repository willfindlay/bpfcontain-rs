// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_CAPABILITY_POLICY_SHARED_H
#define BPFCONTAIN_CAPABILITY_POLICY_SHARED_H

#include "vmlinux.h"

#include "defs.h"

#define CAP_IMPLICIT_DENY_MASK                                                 \
    (BPFCON_CAP_SYS_MODULE | BPFCON_CAP_SYS_BOOT | BPFCON_CAP_MAC_ADMIN |      \
     BPFCON_CAP_MAC_OVERRIDE | BPFCON_CAP_BPF | BPFCON_CAP_PERFMON |           \
     BPFCON_CAP_AUDIT_READ | BPFCON_CAP_AUDIT_CONTROL)

/**
 * Linux capabilities encoded as a bitmask.
 */
typedef enum {
    BPFCON_CAP_CHOWN              = (1ULL << 0),
    BPFCON_CAP_DAC_OVERRIDE       = (1ULL << 1),
    BPFCON_CAP_DAC_READ_SEARCH    = (1ULL << 2),
    BPFCON_CAP_FOWNER             = (1ULL << 3),
    BPFCON_CAP_FSETID             = (1ULL << 4),
    BPFCON_CAP_KILL               = (1ULL << 5),
    BPFCON_CAP_SETGID             = (1ULL << 6),
    BPFCON_CAP_SETUID             = (1ULL << 7),
    BPFCON_CAP_SETPCAP            = (1ULL << 8),
    BPFCON_CAP_LINUX_IMMUTABLE    = (1ULL << 9),
    BPFCON_CAP_NET_BIND_SERVICE   = (1ULL << 10),
    BPFCON_CAP_NET_BROADCAST      = (1ULL << 11),
    BPFCON_CAP_NET_ADMIN          = (1ULL << 12),
    BPFCON_CAP_NET_RAW            = (1ULL << 13),
    BPFCON_CAP_IPC_LOCK           = (1ULL << 14),
    BPFCON_CAP_IPC_OWNER          = (1ULL << 15),
    BPFCON_CAP_SYS_MODULE         = (1ULL << 16),
    BPFCON_CAP_SYS_RAWIO          = (1ULL << 17),
    BPFCON_CAP_SYS_CHROOT         = (1ULL << 18),
    BPFCON_CAP_SYS_PTRACE         = (1ULL << 19),
    BPFCON_CAP_SYS_PACCT          = (1ULL << 20),
    BPFCON_CAP_SYS_ADMIN          = (1ULL << 21),
    BPFCON_CAP_SYS_BOOT           = (1ULL << 22),
    BPFCON_CAP_SYS_NICE           = (1ULL << 23),
    BPFCON_CAP_SYS_RESOURCE       = (1ULL << 24),
    BPFCON_CAP_SYS_TIME           = (1ULL << 25),
    BPFCON_CAP_SYS_TTY_CONFIG     = (1ULL << 26),
    BPFCON_CAP_MKNOD              = (1ULL << 27),
    BPFCON_CAP_LEASE              = (1ULL << 28),
    BPFCON_CAP_AUDIT_WRITE        = (1ULL << 29),
    BPFCON_CAP_AUDIT_CONTROL      = (1ULL << 30),
    BPFCON_CAP_SETFCAP            = (1ULL << 31),
    BPFCON_CAP_MAC_OVERRIDE       = (1ULL << 32),
    BPFCON_CAP_MAC_ADMIN          = (1ULL << 33),
    BPFCON_CAP_SYSLOG             = (1ULL << 34),
    BPFCON_CAP_WAKE_ALARM         = (1ULL << 35),
    BPFCON_CAP_BLOCK_SUSPEND      = (1ULL << 36),
    BPFCON_CAP_AUDIT_READ         = (1ULL << 37),
    BPFCON_CAP_PERFMON            = (1ULL << 38),
    BPFCON_CAP_BPF                = (1ULL << 39),
    BPFCON_CAP_CHECKPOINT_RESTORE = (1ULL << 40),
} capability_t;

/**
 * Policy value for capability policies.
 */
typedef struct {
	// A vector of capabilities to allow
    capability_t allow;
	// A vector of capabilities to deny
    capability_t taint;
	// A vector of capabilities to deny
    capability_t deny;
} __PACKED cap_policy_val_t;

/**
 * Policy key for capability policies.
 */
typedef struct {
	// ID of the policy
    u64 policy_id;
} __PACKED cap_policy_key_t;

#endif /* ifndef BPFCONTAIN_CAPABILITY_POLICY_SHARED_H */

