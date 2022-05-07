// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Main entrypoint for BPFContain, uses the multiple subcommands pattern.

use clap::Parser;

use bpfcontain::{cli::Cli, log::log_error};

fn main() {
    let cli = Cli::parse();
    let result = cli.run();

    // Log results and exit with error code
    if let Err(e) = result {
        log_error(e, None);
        std::process::exit(1);
    }
}
