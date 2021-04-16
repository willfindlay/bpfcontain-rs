// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{Context as _, Result};
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

/// Configure logging
pub fn configure(log_level: LevelFilter, log_file: &str) -> Result<()> {
    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}] {h([{l}])}: {m}\n",
        )))
        .build();

    let filename_fmt = {
        let mut s = log_file.to_string();
        s.push_str(".{}");
        s
    };

    let policy = CompoundPolicy::new(
        Box::new(SizeTrigger::new(100 * u64::pow(1024, 2))),
        Box::new(FixedWindowRoller::builder().build(filename_fmt.as_str(), 10)?),
    );

    let file = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}] [{l}]: {m}\n",
        )))
        .build(log_file, Box::new(policy))
        .context("Failed to configure logging to file")?;

    let config = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(stderr)))
        .appender(Appender::builder().build("file", Box::new(file)))
        .build(
            Root::builder()
                .appender("stderr")
                .appender("file")
                .build(log_level),
        )
        .context("Failed to create logging configuration object")?;

    log4rs::init_config(config).context("Failed to configure logging")?;

    Ok(())
}
