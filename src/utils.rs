// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};

/// Bump the rlimit for memlock up to full capacity.
/// This is required to load even reasonably sized eBPF maps.
///
/// Borrowed this function from [the libbpf-rf
/// docs](https://github.com/libbpf/libbpf-rs/blob/master/examples/runqslower/src/main.rs).
pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
