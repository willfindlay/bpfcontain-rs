// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::Result;
use clap::ArgMatches;

use crate::bpf;
use crate::utils::{bump_memlock_rlimit, get_symbol_offset};

/// Main entrypoint for BPF program functionality.
pub fn main(args: &ArgMatches) -> Result<()> {
    log::info!("Initializing BPF objects...");

    log::debug!("Bumping memlock...");
    bump_memlock_rlimit()?;

    log::debug!("Initializing skeleton builder...");
    let mut skel_builder = bpf::ProgsSkelBuilder::default();
    if args.occurrences_of("v") >= 3 {
        skel_builder.obj_builder.debug(true);
    }

    log::debug!("Opening skeleton...");
    let mut open_skel = skel_builder.open()?;

    log::debug!("Setting data...");
    // TODO: Write to skeleton sections here

    log::debug!("Loading skeleton...");
    let mut skel = open_skel.load()?;

    log::debug!("Attaching BPF objects...");
    // TODO: Attach BPF programs here
    //skel.attach()?;

    log::info!("Loaded and attached BPF objects!");

    Ok(())
}

/// Extends [`libbpf_rs::Program`] with a method to attach a uprobe to a given
/// `symbol_name` within the ELF binary located at `binary_path`.
trait SymbolUprobeExt {
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: &str,
        symbol_name: &str,
    ) -> Result<libbpf_rs::Link>;
}

impl SymbolUprobeExt for libbpf_rs::Program {
    /// Attach a uprobe to a given `symbol_name` within the ELF binary located
    /// at `binary_path`.
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: &str,
        symbol_name: &str,
    ) -> Result<libbpf_rs::Link> {
        // Grab the symbol offset, if we can find it
        let func_offset = get_symbol_offset(binary_path, symbol_name)?;

        // Use the offset we found to attach the uprobe or uretprobe
        let result = self.attach_uprobe(retprobe, pid, binary_path, func_offset)?;

        Ok(result)
    }
}
