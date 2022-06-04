// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 01, 2022  William Findlay  Created this.

use anyhow::{anyhow, Result};

fn do_ioctl(
    operation: super::raw::bpfcontain_request_t,
    arguments: &mut super::raw::bpfcontain_ioctl_t,
) -> Result<()> {
    match (
        unsafe { nix::libc::ioctl(-1, operation as u64, arguments as *mut _ as *mut u8) },
        nix::errno::errno(),
    ) {
        (0, _) => Ok(()),
        (_, rc) if rc == nix::libc::ENOTTY || rc == nix::libc::EBADF => {
            Err(anyhow!("Failed to call into probe. Is BPFContain running?"))
        }
        (_, rc) if rc == nix::libc::EPERM => Err(anyhow!("Permission denied")),
        (_, rc) if rc == nix::libc::ENOMEM => Err(anyhow!("Map lookup/update failed")),
        (_, rc) if rc == nix::libc::ENOENT => Err(anyhow!("Policy does not exist")),
        (_, rc) if rc == nix::libc::ESRCH => Err(anyhow!("Failed to look up process")),
        (_, rc) if rc == nix::libc::EINVAL => Err(anyhow!("Unknown command")),
        (_, rc) => Err(anyhow!("Unhandled error: {rc}")),
    }
}

pub fn confine(policy_id: u64, pid: Option<u32>) -> Result<()> {
    let mut args = super::raw::bpfcontain_ioctl_t::default();
    unsafe {
        *args.confine.as_mut() = super::raw::bpfcontain_ioctl_confine_t {
            policy_id,
            pid: if let Some(pid) = pid { pid } else { 0 },
        };
    }

    do_ioctl(
        super::raw::bpfcontain_request_t::BPFCONTAIN_OP_CONFINE,
        &mut args,
    )
}
