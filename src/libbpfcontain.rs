// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::{bail, Result};

/// Include bindings from [`bindings.rs`](lib/bindings.rs)
mod bindings {
    include!("lib/bindings.rs");
}

/// Place the current process into a container with ID `container_id`.
pub fn containerize(container_id: libc::c_ulong) -> Result<()> {
    let result = unsafe { bindings::containerize(container_id) };

    match result {
        0 => Ok(()),
        n if n == -libc::EAGAIN => bail! {"Failed to call into uprobe"},
        n if n == -libc::ENOENT => bail! {"No such container with ID {}", container_id},
        n if n == -libc::EINVAL => bail! {"Process is already containerized or no room in map"},
        n => bail! {"Unknown error {}", n},
    }
}
