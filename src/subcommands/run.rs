// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! The `run` subcommand.

use std::{os::unix::process::CommandExt, process::Command};

use anyhow::{Context as _, Result};

use crate::policy::Policy;

/// Main entrypoint into launching a container.
pub fn main(policy_file: &str, cmd: &[String]) -> Result<()> {
    // Get the command from args if it was provided
    let cmd = if cmd.len() > 0 {
        Some(cmd.join(" "))
    } else {
        None
    };

    // Parse policy
    let policy = Policy::from_path(policy_file).context("Failed to parse policy")?;

    // Run the process
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
                policy.containerize().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to confine process: {:?}", e),
                    )
                })
            })
    }
    .exec();

    Err(anyhow::Error::from(err))
}
