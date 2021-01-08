// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::Result;
use std::process::Command;

fn setup() -> Result<()> {
    let comm = Command::new("target/debug/bpfcontain-rs")
        .arg("daemon")
        .arg("fg")
        .spawn()?;

    Ok(())
}

fn main() -> Result<()> {
    setup()?;

    Ok(())
}
