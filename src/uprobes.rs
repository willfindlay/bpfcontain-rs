// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};

use crate::policy::Policy;

pub extern "C" fn do_containerize(_retp: *const i32, _policy_id: u64) {}

/// Place the current process into a container with ID `policy_id`.
pub fn containerize(policy: &Policy) -> Result<()> {
    let ret: i32 = -libc::EAGAIN;

    do_containerize(&ret as *const i32, policy.policy_id());

    match ret {
        0 => Ok(()),
        n if n == -libc::EAGAIN => bail!("Failed to call into uprobe"),
        n if n == -libc::ENOENT => bail!("No such container with ID {}", policy.policy_id()),
        n if n == -libc::EINVAL => bail!("Process is already containerized or no room in map"),
        n => bail!("Unknown error {}", n),
    }
}
