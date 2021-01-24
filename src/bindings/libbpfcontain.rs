// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Function bindings for libbpfcontain.

use super::raw;
use anyhow::{bail, Result};

/// Place the current process into a container with ID `policy_id`.
pub fn containerize(policy_id: libc::c_ulong) -> Result<()> {
    let result = unsafe { raw::containerize(policy_id) };

    match result {
        0 => Ok(()),
        n if n == -libc::EAGAIN => bail!("Failed to call into uprobe"),
        n if n == -libc::ENOENT => bail!("No such container with ID {}", policy_id),
        n if n == -libc::EINVAL => bail!("Process is already containerized or no room in map"),
        n => bail!("Unknown error {}", n),
    }
}
