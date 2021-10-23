// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Logger configuration logic.

use anyhow::{Context as _, Error, Result};
use log::{Level, LevelFilter};
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

/// Log an error
pub fn log_error(err: Error, level: Option<Level>) {
    let chain = err.chain();

    for (i, err) in chain.enumerate() {
        // Treat first element in chain differently.
        // There might be a more Rusty way to do this, but whatever...
        if i == 0 {
            if let Some(level) = level {
                log::log!(level, "{}", err)
            } else {
                log::error!("{}", err)
            }
            continue;
        }
        if let Some(level) = level {
            log::log!(level, "\t| {}", err)
        } else {
            log::error!("\t| {}", err)
        }
    }
}

/// Configure logging
pub fn configure(log_level: LevelFilter, log_file: Option<&str>) -> Result<()> {
    let config_builder = Config::builder();

    // Log to stderr
    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{h([{l}])}: {m}\n")))
        .target(Target::Stderr)
        .build();
    let config_builder =
        config_builder.appender(Appender::builder().build("stderr", Box::new(stderr)));

    // Log to file
    let config_builder = match log_file {
        Some(log_file) => {
            let file = FileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "[{d(%Y-%m-%d %H:%M:%S)}] [{l}]: {m}\n",
                )))
                .build(log_file)
                .context("Failed to configure logging to file")?;
            config_builder.appender(Appender::builder().build("file", Box::new(file)))
        }
        None => config_builder,
    };

    // Configure root logger
    let root_builder = Root::builder().appender("stderr");
    let root_builder = match log_file {
        Some(_) => root_builder.appender("file"),
        None => root_builder,
    };

    // Build final config
    let config = config_builder
        .build(root_builder.build(log_level))
        .context("Failed to create logging configuration object")?;

    // Configure the logger
    log4rs::init_config(config).context("Failed to configure logging")?;

    Ok(())
}
