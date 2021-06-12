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

/// Main entrypoint into launching a container.
pub fn main(args: &ArgMatches, config: &Settings) -> Result<()> {
    // Initialize the logger
    // We don't want to log to any file, just stderr
    crate::log::configure(config.daemon.verbosity, None)?;

    // Pretty print current config
    log::debug!("{:#?}", config);

    // Configure policy path
    let policy_dir = Path::new(&config.policy.dir);
    let policy_file = Path::new(
        args.value_of("policy")
            .context("Failed to get path to policy file")?,
    );
    let path = policy_dir.join(policy_file);

    // Get the command from args if it was provided
    let cmd = args
        .values_of("command")
        .map(|cmd| cmd.collect::<Vec<&str>>().join(" "));

    // Parse policy
    let policy = Policy::from_path(path).context("Failed to parse policy")?;

    run_container_by_policy(&policy, cmd.as_deref())
}

/// Run a container according to the corresponding `policy`, overriding cmd if `cmd` is
/// provided.
pub fn run_container_by_policy(policy: &Policy, cmd: Option<&str>) -> Result<()> {
    // Use provided command or command specified in policy
    let cmd = {
        if let Some(cmd) = cmd {
            cmd.split_whitespace().collect::<Vec<_>>()
        } else {
            policy
                .cmd
                .as_ref()
                .context(
                    "No default command provided for this policy.
                    Either specify it using -- <CMD> [ARGS...] or modify the policy file.",
                )?
                .split_whitespace()
                .collect::<Vec<_>>()
        }
    };

    // Parse out args
    let args: Vec<_> = cmd.iter().skip(1).collect();

    // Spawn process
    let policy = policy.to_owned();
    let err = unsafe {
        Command::new(cmd.get(0).context("Failed to get command")?)
            .args(args)
            .pre_exec(move || {
                // Place this process into a BPFContain container
                policy.containerize().expect("Failed to containerize");
                Ok(())
            })
    }
    .exec();

    bail!("Failed to run {}: {:?}", cmd.get(0).unwrap(), err);
}
