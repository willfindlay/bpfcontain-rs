// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Main entrypoint for BPFContain, uses the multiple subcommands pattern.

use ::anyhow::{bail, Context as _, Result};
use ::clap::{crate_authors, crate_name, crate_version, App, AppSettings, Arg, SubCommand};

use bpfcontain::config;
use bpfcontain::subcommands::daemon;
use bpfcontain::subcommands::run;
use bpfcontain::subcommands::confine;

fn main() -> Result<()> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .about("Container security with eBPF")
        .author(crate_authors!())
        // If the user supplies no arguments, print help
        .setting(AppSettings::ArgRequiredElseHelp)
        // Make all commands print colored help if available
        .global_setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .global(true)
                .help("Sets verbosity. Possible values are -v or -vv"),
        )
        .arg(
            Arg::with_name("q")
                .short("q")
                .global(true)
                .conflicts_with("v")
                .help("Run in quiet mode, only logging warning and errors."),
        )
        .arg(
            Arg::with_name("cfg")
                .long("config")
                .takes_value(true)
                .validator(path_validator)
                .help("Use a different config file"),
        )
        // Daemon-related commands
        .subcommand(
            SubCommand::with_name("daemon")
                .about("Control the BPFContain daemon.")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("start")
                        .about("Start the daemon")
                        .display_order(1),
                )
                .subcommand(
                    SubCommand::with_name("stop")
                        .about("Stop the daemon")
                        .display_order(2),
                )
                .subcommand(
                    SubCommand::with_name("restart")
                        .about("Restart the daemon")
                        .display_order(3),
                )
                .subcommand(
                    SubCommand::with_name("foreground")
                        .about("Run in the foreground")
                        .display_order(4)
                        .visible_alias("fg"),
                ),
        )
        // Run the BPF program without daemonizing
        .subcommand(
            SubCommand::with_name("run")
                .about("Run in the foreground.")
                .arg(
                    Arg::with_name("policy")
                        .required(true)
                        .help("The policy to run"),
                )
                .arg(
                    Arg::with_name("command")
                        .multiple(true)
                        .last(true)
                        .help("Override policy command"),
                ),
        ).subcommand(
            SubCommand::with_name("confine")
                .about("Apply a policy to a container using it's pid")
                .arg(
                    Arg::with_name("pid")
                        .required(true)
                        .help("The containers root process pid"),
                )
                .arg(
                    Arg::with_name("policy")
                    .required(true)
                    .help("The policy to use")
                )
        );

    // Parse arguments
    let args = app.get_matches();

    // Initialize config
    let config = {
        let mut config =
            config::Settings::new(args.value_of("cfg")).context("Failed to load configuration")?;

        // Set verbosity based on -v, -vv arguments
        // Level 0: Use config default
        // Level 1: Debug
        // Level 2: Trace
        match args.occurrences_of("v") {
            0 => {}
            1 => config.daemon.verbosity = log::LevelFilter::Debug,
            _ => config.daemon.verbosity = log::LevelFilter::Trace,
        };

        // Set quiet mode
        if args.is_present("q") {
            config.daemon.verbosity = log::LevelFilter::Warn;
        }

        config
    };

    // Dispatch to subcommand
    match args.subcommand() {
        ("daemon", Some(args)) => daemon::main(args, &config)?,
        ("run", Some(args)) => run::main(args, &config)?,
        ("confine", Some(args)) => confine::main(args, &config)?,
        // TODO: match other subcommands
        (unknown, _) => bail!("Unknown subcommand {}", unknown),
    };

    Ok(())
}

/// Argument validator that ensures a path `arg` exists.
fn path_validator(arg: String) -> Result<(), String> {
    let path = std::path::PathBuf::from(&arg);

    if !path.exists() {
        return Err(format!("Path `{}` does not exist", &arg));
    }

    Ok(())
}
