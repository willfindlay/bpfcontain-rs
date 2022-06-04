#ifndef BPFCONTAIN_CONFIG_H
#define BPFCONTAIN_CONFIG_H

#include "bpf.h"

// Settings
const volatile __weak u32 audit_level;

// Constants
const volatile __weak u32 bpfcontain_pid;
const volatile __weak u32 host_mnt_ns_id;
const volatile __weak u32 host_pid_ns_id;

// Backing id for the root filesystem
volatile __weak u32 root_fs_id = 0;

// Kernel symbols
extern const __weak void init_nsproxy __ksym;
extern const __weak void init_user_ns __ksym;

extern __weak u32 LINUX_KERNEL_VERSION __kconfig;


#endif /* ifndef BPFCONTAIN_CONFIG_H */
