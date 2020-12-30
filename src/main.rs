// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{anyhow, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use simple_logger::SimpleLogger;

mod subcommands;
use subcommands::daemon;

fn main() -> Result<()> {
    let app = App::new("BPFContain")
        .version("0.0.1")
        .about("Container security with eBPF")
        .author("William Findlay <william@williamfindlay.com>")
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .global(true)
                .help("Sets verbosity. Possible values are -v, -vv, or -vvv"),
        )
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
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
                ),
        );

    // Parse the arguments
    let args = app.get_matches();

    // Set log level based on verbosity
    // Level 0: Warning
    // Level 1: Info
    // Level 2: Debug
    // Level 3: Trace
    let log_level = match args.occurrences_of("v") {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        3 | _ => log::LevelFilter::Trace,
    };

    // Initialize the logger
    SimpleLogger::new().with_level(log_level).init()?;

    // Dispatch to subcommand
    let result = match args.subcommand() {
        ("daemon", Some(args)) => daemon::main(args),
        // TODO: match other subcommands
        (unknown, _) => Err(anyhow!("Unknown subcommand {}", unknown)),
    };

    // Log errors if they bubble up
    if let Err(e) = &result {
        log::error!("Error: {}", e);
    }

    result
}
