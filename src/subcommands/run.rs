// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{Context, Result};
use clap::ArgMatches;
use std::ffi::CString;
use std::path::Path;

use crate::config::Settings;
use crate::libbpfcontain::containerize;
use crate::policy::Policy;

pub fn main(args: &ArgMatches, config: &Settings) -> Result<()> {
    // Configure policy path
    let policy_dir = Path::new(&config.policy.dir);
    let policy_file = Path::new(
        args.value_of("policy")
            .context("Failed to get path to policy file")?,
    );
    let policy_path = policy_dir.join(policy_file);

    // Parse policy
    let policy = Policy::from_path(policy_path).context("Failed to parse policy")?;

    // Containerize
    containerize(policy.policy_id()).context("Failed to containerize")?;

    // Parse out command
    let command = policy
        .cmd
        .split_whitespace()
        .nth(0)
        .context("Failed to get command")?;
    // Parse out args
    let args: Vec<_> = policy.cmd.split_whitespace().skip(1).collect();

    nix::unistd::execv(
        &CString::new(command).expect("Failed to create C string"),
        &args
            .iter()
            .map(|&s| CString::new(s).expect("Failed to create C string"))
            .collect::<Vec<_>>()[..],
    )
    .context("Failed to execve")?;

    Ok(())
}
