// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Function bindings for libbpfcontain.

use anyhow::{bail, Result};

use super::raw;
use crate::policy::Policy;

/// Place the current process into a container with ID `policy_id`.
pub fn containerize(policy: &Policy) -> Result<()> {
    let result = unsafe {
        raw::containerize(
            policy.policy_id(),
            policy.default_taint() as u8,
            policy.default_deny() as u8,
        )
    };

    match result {
        0 => Ok(()),
        n if n == -libc::EAGAIN => bail!("Failed to call into uprobe"),
        n if n == -libc::ENOENT => bail!("No such container with ID {}", policy.policy_id()),
        n if n == -libc::EINVAL => bail!("Process is already containerized or no room in map"),
        n => bail!("Unknown error {}", n),
    }
}
