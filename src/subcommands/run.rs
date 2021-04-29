// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! The `run` subcommand.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context as _, Result};
use clap::ArgMatches;

use crate::config::Settings;
use crate::policy::Policy;
use crate::uprobes::containerize;

/// Main entrypoint into launching a container.
pub fn main(args: &ArgMatches, config: &Settings) -> Result<()> {
    // Initialize the logger
    // We don't want to log to any file, just stderr
    crate::log::configure(config.daemon.verbosity, None)?;

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

    // Get entrypoint as a vector of strings
    let cmd_vec = {
        if let Some(cmd) = args
            .values_of("command")
            .map(|vals| vals.collect::<Vec<_>>())
        {
            cmd
        } else {
            policy.cmd.split_whitespace().collect::<Vec<_>>()
        }
    };

    // Parse out command
    let command = cmd_vec.get(0).context("Failed to get command")?;

    // Parse out args
    let args: Vec<_> = cmd_vec.iter().skip(1).collect();

    let err = Command::new(command).args(args).exec();

    bail!("Failed to run {}: {:?}", command, err);
}
