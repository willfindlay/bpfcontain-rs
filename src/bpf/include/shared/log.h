// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay

#ifndef BPFCONTAIN_LOG_SHARED_H
#define BPFCONTAIN_LOG_SHARED_H

#define __BPFCONTAIN_LOG_MSG_SIZE 4096

typedef enum {
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_TRACE,
	__LOG_UNDEF,
} LogLevel;

typedef struct {
	LogLevel level;
	char msg[__BPFCONTAIN_LOG_MSG_SIZE];
} BPFContainLog;

#endif /* ifndef BPFCONTAIN_LOG_SHARED_H */
