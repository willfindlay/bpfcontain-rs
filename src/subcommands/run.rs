// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::ArgMatches;

use crate::bindings::containerize;
use crate::config::Settings;
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
    containerize(&policy).context("Failed to containerize")?;

    // Parse out command
    let command = policy
        .cmd
        .split_whitespace()
        .nth(0)
        .context("Failed to get command")?;
    // Parse out args
    let args: Vec<_> = policy.cmd.split_whitespace().skip(1).collect();

    let err = Command::new(command).args(args).exec();

    bail!("Failed to run {}: {:?}", command, err);
}
