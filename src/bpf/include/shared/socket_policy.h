// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_SOCKET_POLICY_SHARED_H
#define BPFCONTAIN_SOCKET_POLICY_SHARED_H

#include "vmlinux.h"

#include "defs.h"

/**
 * Socket access categories */
typedef enum {
	// Socket connects to the Internet (AF_INET, AF_INET6, etc.)
    BPFCON_NET_WWW = (1U << 0),
	// Socket connects to another process (AF_UNIX)
    BPFCON_NET_IPC = (1U << 1),
} net_category_t;

/**
 * Socket operations */
typedef enum {
	// Connect to a socket
    BPFCON_NET_CONNECT  = (1U << 0),
	// Bind a socket
    BPFCON_NET_BIND     = (1U << 1),
	// Accept a connection on a socket
    BPFCON_NET_ACCEPT   = (1U << 2),
	// Listen on a socket
    BPFCON_NET_LISTEN   = (1U << 3),
	// Send data on a socket
    BPFCON_NET_SEND     = (1U << 4),
	// Receive data from a socket
    BPFCON_NET_RECV     = (1U << 5),
	// Create a socket
    BPFCON_NET_CREATE   = (1U << 6),
	// Shutdown a socket
    BPFCON_NET_SHUTDOWN = (1U << 7),
} net_operation_t;

/**
 * Policy key for socket access */
typedef struct {
    u64 policy_id;
} __PACKED net_policy_key_t;

/**
 * Polciy value for socket actions */
typedef struct {
    net_operation_t allow;
    net_operation_t taint;
    net_operation_t deny;
} __PACKED net_policy_val_t;

#endif /* ifndef BPFCONTAIN_SOCKET_POLICY_SHARED_H */
