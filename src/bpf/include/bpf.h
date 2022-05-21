#ifndef BPFCONTAIN_BPF_H
#define BPFCONTAIN_BPF_H

// This must be first
#include <vmlinux.h>

// These must be below vmlinux.h
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

#define core(x) __builtin_preserve_access_index(x)

#endif /* ifndef BPFCONTAIN_BPF_H */
