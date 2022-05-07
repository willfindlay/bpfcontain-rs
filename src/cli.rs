// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! BPFContain's CLI

use std::path::PathBuf;

use anyhow::Result;
use clap_derive::{Parser, Subcommand};

use crate::subcommands::{self, daemon};

/// The BPFContain CLI
#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about = "Container security with eBPF",
    arg_required_else_help(true)
)]
pub struct Cli {
    /// The subcommand to run
    #[clap(subcommand)]
    subcommand: Cmd,
    /// Verbosity level for log messages (-1 or lower is silent, 0 is quiet, 1 is info,
    /// 2 is debug, 3 is trace). Defaults to value defined in BPFContain configs.
    #[clap(global = true, long, short)]
    verbose: Option<i8>,
    /// Config file to read from. If this file does not exist, sensible defaults will be
    /// applied
    #[clap(global = true, long, short, default_value = "/etc/bpfcontain.yml")]
    config: PathBuf,
}

impl Cli {
    pub fn run(&self) -> Result<()> {
        let mut config = crate::config::Settings::new(&self.config)?;

        if let Some(verbose) = self.verbose {
            match verbose {
                0 => config.verbosity = log::LevelFilter::Warn,
                1 => config.verbosity = log::LevelFilter::Info,
                2 => config.verbosity = log::LevelFilter::Debug,
                3 => config.verbosity = log::LevelFilter::Trace,
                _ => config.verbosity = log::LevelFilter::Off,
            }
        }

        if let Cmd::Daemon { .. } = self.subcommand {
            crate::log::configure(config.verbosity, Some(config.daemon.log_file.as_str()))?;
        } else {
            crate::log::configure(config.verbosity, None)?;
        }

        log::trace!("CLI arguments: {:#?}", self);
        log::debug!("Running with config: {:#?}", &config);

        self.subcommand.run(&config)
    }
}

/// BPFContain subcommand
#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Control the BPFContain daemon
    Daemon {
        /// The subcommand to run
        #[clap(subcommand)]
        subcommand: Daemon,
    },
    /// Run a process under a BPFContain policy
    Run {
        /// The policy to use
        policy: String,
        /// The command to run and its arguments
        #[clap(last(true))]
        command: Vec<String>,
    },
    /// Confine a running process using its PID or container using its root pid
    Confine {
        /// The policy to use
        policy: String,
        /// The command to run and its arguments
        pid: u32,
    },
}

impl Cmd {
    pub(crate) fn run(&self, config: &crate::config::Settings) -> Result<()> {
        match self {
            Cmd::Daemon { subcommand } => subcommand.run(config),
            Cmd::Run { policy, command } => subcommands::run::main(policy, command),
            Cmd::Confine { policy, pid } => subcommands::confine::main(policy, *pid),
        }
    }
}

/// Subcommand for the daemon
#[derive(Subcommand, Debug)]
#[clap(arg_required_else_help(true))]
pub enum Daemon {
    /// Start the daemon
    #[clap(display_order(1))]
    Start,
    /// Stop the daemon
    #[clap(display_order(2))]
    Stop,
    /// Restart the daemon
    #[clap(display_order(3))]
    Restart,
    /// Run daemon in the foreground isntead of daemonizing
    #[clap(display_order(4), visible_alias = "fg")]
    Foreground,
}

impl Daemon {
    pub(crate) fn run(&self, config: &crate::config::Settings) -> Result<()> {
        daemon::main(self, config)
    }
}
