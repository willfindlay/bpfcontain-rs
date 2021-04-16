// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use ::anyhow::{bail, Result};
use ::clap::{App, AppSettings, Arg, SubCommand};

use bpfcontain::config;
use bpfcontain::subcommands::daemon;
use bpfcontain::subcommands::run;

fn main() -> Result<()> {
    let app = App::new("BPFContain")
        .version("0.0.1")
        .about("Container security with eBPF")
        .author("William Findlay <william@williamfindlay.com>")
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
        );

    // Parse arguments
    let args = app.get_matches();

    // Initialize config
    let config_path = args.value_of("cfg");
    let mut config = config::Settings::new(config_path).expect("Failed to load configuration");

    // Set log level based on verbosity
    // Level 0: Info
    // Level 1: Debug
    // Level 2: Trace
    match args.occurrences_of("v") {
        0 => {}
        1 => config.daemon.loglevel = log::LevelFilter::Debug,
        2 | _ => config.daemon.loglevel = log::LevelFilter::Trace,
    };

    if args.occurrences_of("v") >= 2 {
        // Pretty print current config
        println!("{:#?}", config);
    }

    // Dispatch to subcommand
    match args.subcommand() {
        ("daemon", Some(args)) => daemon::main(args, &config)?,
        ("run", Some(args)) => run::main(args, &config)?,
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
