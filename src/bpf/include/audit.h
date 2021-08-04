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
static audit_level_t decision_to_audit_level(policy_decision_t decision,
                                             bool default_deny)
{
    if (decision & BPFCON_DENY) {
        return AUDIT_DENY;
    } else if (decision & BPFCON_TAINT) {
        return AUDIT_TAINT;
    } else if (decision & BPFCON_ALLOW) {
        return AUDIT_ALLOW;
    } else if (default_deny) {
        return AUDIT_DENY;
    }
    return AUDIT__NONE;
}

/**
 * __alloc_audit_event() - Allocate space in the ring buffer for an audit event
 * and populate its common fields. This function should not be called directly.
 *
 * @FIXME: Add documentation
 */
static audit_data_t *__alloc_audit_event(u64 policy_id, audit_type_t type,
                                         audit_level_t level)
{
    audit_data_t *event =
        bpf_ringbuf_reserve(&__audit_buf, sizeof(audit_data_t), 0);
    if (!event) {
        bpf_printk("Failed to allocate audit event!");
        return NULL;
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->policy_id = policy_id;
    event->tgid      = bpf_get_current_pid_tgid();
    event->pid       = bpf_get_current_pid_tgid() >> 32;
    event->level     = level;
    event->type      = type;

    return event;
}

/**
 * alloc_audit_event() - Allocate space in the ring buffer for an audit event
 * and populate its common fields.
 *
 * @FIXME: Add documentation
 */
#define alloc_audit_event(policy_id, type, level)                              \
    ({                                                                         \
        void *event = NULL;                                                    \
        if (should_audit(level) && level > AUDIT__NONE)                        \
            event = __alloc_audit_event(policy_id, type, level);               \
        event;                                                                 \
    })

/**
 * submit_audit_event() - Submit an audit event to userspace.
 *
 * @FIXME: Add documentation
 */
#define submit_audit_event(event) bpf_ringbuf_submit(event, 0);

#endif /* ifndef AUDIT_H */
