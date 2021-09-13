// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 06, 2020  William Findlay  Created this.

#ifndef POLICY_H
#define POLICY_H

#include "structs.h"

/**
 * apply_taint() - Alter a policy decision based on the taintedness of a
 * container.
 *
 * Params:
 *     @container: a pointer to the container
 *     @default_deny: true if the access should be default deny regardless of
 * taint
 *     @decision: an initial policy decision value
 *
 * Returns:
 *     The new policy decision
 */
policy_decision_t apply_taint(container_t *container, u8 default_deny,
                              policy_decision_t decision)
{
    if ((container->tainted || default_deny) && !(decision & BPFCON_ALLOW))
        return decision | BPFCON_DENY;
    return decision;
}

#endif /* ifndef POLICY_H */
