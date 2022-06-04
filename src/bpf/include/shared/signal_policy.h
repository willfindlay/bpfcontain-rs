// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_SIGNAL_POLICY_SHARED_H
#define BPFCONTAIN_SIGNAL_POLICY_SHARED_H

#include "vmlinux.h"

#include "defs.h"
#include "policy.h"

/**
 * Encode Linux signals as a bitmask */
typedef enum {
    BPFCON_SIGCHK    = (1ULL << 0),
    BPFCON_SIGHUP    = (1ULL << 1),
    BPFCON_SIGINT    = (1ULL << 2),
    BPFCON_SIGQUIT   = (1ULL << 3),
    BPFCON_SIGILL    = (1ULL << 4),
    BPFCON_SIGTRAP   = (1ULL << 5),
    BPFCON_SIGABRT   = (1ULL << 6), // SIGIOT has the same number as SIGABRT
    BPFCON_SIGBUS    = (1ULL << 7),
    BPFCON_SIGFPE    = (1ULL << 8),
    BPFCON_SIGKILL   = (1ULL << 9),
    BPFCON_SIGUSR1   = (1ULL << 10),
    BPFCON_SIGSEGV   = (1ULL << 11),
    BPFCON_SIGUSR2   = (1ULL << 12),
    BPFCON_SIGPIPE   = (1ULL << 13),
    BPFCON_SIGALRM   = (1ULL << 14),
    BPFCON_SIGTERM   = (1ULL << 15),
    BPFCON_SIGSTKFLT = (1ULL << 16),
    BPFCON_SIGCHLD   = (1ULL << 17),
    BPFCON_SIGCONT   = (1ULL << 18),
    BPFCON_SIGSTOP   = (1ULL << 19),
    BPFCON_SIGTSTP   = (1ULL << 20),
    BPFCON_SIGTTIN   = (1ULL << 21),
    BPFCON_SIGTTOU   = (1ULL << 22),
    BPFCON_SIGURG    = (1ULL << 23),
    BPFCON_SIGXCPU   = (1ULL << 24),
    BPFCON_SIGXFSZ   = (1ULL << 25),
    BPFCON_SIGVTALRM = (1ULL << 26),
    BPFCON_SIGPROF   = (1ULL << 27),
    BPFCON_SIGWINCH  = (1ULL << 28),
    BPFCON_SIGIO     = (1ULL << 29), // SIGPOLL has the same number as SIGIO
    BPFCON_SIGPWR    = (1ULL << 30),
    BPFCON_SIGSYS    = (1ULL << 31),
} signal_operation_t;

/**
 * Policy key for signals */
typedef struct {
	// Sender policy id
    u64 sender_id;
	// Receiver policy id
    u64 receiver_id;
} __PACKED signal_policy_key_t;

/**
 * Policy value for signals */
typedef struct {
	// Signals to allow
    signal_operation_t allow;
	// Signals to taint
    signal_operation_t taint;
	// Signals to deny
    signal_operation_t deny;
} __PACKED signal_policy_val_t;

#endif /* ifndef BPFCONTAIN_SIGNAL_POLICY_SHARED_H */
