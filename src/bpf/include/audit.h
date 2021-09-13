// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef AUDIT_H
#define AUDIT_H

#include "map_defs.h"
#include "structs.h"

/**
 * decision_to_audit_level() - Convert a policy decision into the appropriate
 * audit level.
 *
 * @FIXME: Add documentation
 */
static audit_level_t decision_to_audit_level(policy_decision_t decision)
{
    // CORRECTNESS: This type cast is correct since we assume that
    // the first three members of audit_level_t cleanly map to the
    // only three members of policy_decision_t. If this assumption
    // somehow later becomes invalid, this will need to be revisited.
    return (audit_level_t)decision;
}

/**
 * __alloc_audit_event() - Allocate space in the ring buffer for an audit event
 * and populate its common fields. This function should not be called directly.
 *
 * @FIXME: Add documentation
 */
static audit_data_t *__alloc_audit_event(process_t *process,
                                         container_t *container,
                                         audit_type_t type, audit_level_t level,
                                         policy_decision_t decision)
{
    audit_data_t *event =
        bpf_ringbuf_reserve(&__audit_buf, sizeof(audit_data_t), 0);
    if (!event) {
        bpf_printk("Failed to allocate audit event!");
        return NULL;
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (container) {
        event->container_id = container->container_id;
        event->policy_id    = container->policy_id;
    }
    if (process) {
        event->pid    = process->host_pid;
        event->ns_pid = process->pid;
    }
    event->level    = level;
    event->type     = type;
    event->decision = decision;

    return event;
}

/**
 * alloc_audit_event() - Allocate space in the ring buffer for an audit event
 * and populate its common fields.
 *
 * @FIXME: Add documentation
 */
#define alloc_audit_event(process, container, type, level, decision)           \
    ({                                                                         \
        void *event = NULL;                                                    \
        if (should_audit(level) && level > AUDIT__NONE)                        \
            event = __alloc_audit_event(process, container, type, level,       \
                                        decision);                             \
        event;                                                                 \
    })

/**
 * submit_audit_event() - Submit an audit event to userspace.
 *
 * @FIXME: Add documentation
 */
#define submit_audit_event(event) bpf_ringbuf_submit(event, 0);

#endif /* ifndef AUDIT_H */
