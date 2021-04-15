// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{anyhow, Context, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use log::LevelFilter;
use stderrlog::StdErrLog;
use syslog::{BasicLogger, Facility, Formatter3164};

use bpfcontain::*;

use subcommands::daemon;
use subcommands::run;

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

    // Set log level based on verbosity
    // Level 0: Info
    // Level 1: Debug
    // Level 2: Trace
    let log_level = match args.occurrences_of("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 | _ => log::LevelFilter::Trace,
    };

    // Initialize the logger
    let foreground = match args.subcommand() {
        ("daemon", Some(args)) => args.subcommand_name() == Some("foreground"),
        _ => true,
    };
    println!("running in foreground: {:?}", foreground);
    configure_logging(log_level, foreground).expect("Failed to configure logging");

    // Initialize config
    let config_path = args.value_of("cfg");
    let config = config::Settings::new(config_path).expect("Failed to load configuration");

    // Pretty print current config to debug logs
    log::debug!("{:#?}", config);

    // Dispatch to subcommand
    let result = match args.subcommand() {
        ("daemon", Some(args)) => daemon::main(args, &config).context("Daemon exited with error"),
        ("run", Some(args)) => run::main(args, &config).context("Run exited with error"),
        // TODO: match other subcommands
        (unknown, _) => Err(anyhow!("Unknown subcommand {}", unknown)),
    };

    // Log errors if they bubble up
    // This effectively re-routes error messages to the log file
    if let Err(e) = result {
        log::error!("{:?}", e);
        std::process::exit(1);
    }

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

/// Configure logging to either log to syslog or standard error
fn configure_logging(log_level: LevelFilter, stderr: bool) -> Result<()> {
    if stderr {
        let verbosity = match log_level {
            LevelFilter::Error => 0,
            LevelFilter::Warn => 1,
            LevelFilter::Info => 2,
            LevelFilter::Debug => 3,
            _ => 4,
        };

        stderrlog::new().verbosity(verbosity).init()
    } else {
        let formatter = Formatter3164 {
            facility: Facility::LOG_DAEMON,
            hostname: None,
            process: "bpfcontain".into(),
            pid: 0,
        };

        let logger = syslog::unix(formatter).expect("Failed to connect to syslog");

        log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .map(|()| log::set_max_level(log_level))
    }
    .context("Failed to initialize logger")?;

    Ok(())
}
