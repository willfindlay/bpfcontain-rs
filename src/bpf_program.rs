// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};
use clap::ArgMatches;

use crate::bpf;
use crate::utils::{bump_memlock_rlimit, get_symbol_offset};

/// Main entrypoint for BPF program functionality.
pub fn main(args: &ArgMatches) -> Result<()> {
    log::info!("Initializing BPF objects...");

    log::debug!("Bumping memlock...");
    bump_memlock_rlimit()?;

    log::debug!("Initializing skeleton builder...");
    let mut skel_builder = bpf::BpfcontainSkelBuilder::default();
    if args.occurrences_of("v") >= 3 {
        skel_builder.obj_builder.debug(true);
    }

    log::debug!("Opening skeleton...");
    let mut open_skel = match skel_builder.open() {
        Ok(open_skel) => open_skel,
        Err(e) => bail!("Failed to open skeleton: {}", e),
    };
    //open_skel.bss();

    log::debug!("Setting data...");
    // TODO: Write to skeleton sections here
    //open_skel.rodata().debug = 1;

    log::debug!("Loading skeleton...");
    let mut skel = match open_skel.load() {
        Ok(skel) => skel,
        Err(e) => bail!("Failed to load skeleton: {}", e),
    };

    log::debug!("Attaching BPF objects...");
    skel.attach()?;
    skel.progs().do_containerize().attach_uprobe_symbol(
        false,
        -1,
        String::from("/usr/lib/libbpfcontain.so"),
        String::from("do_containerize"),
    )?;

    // TODO: Attach BPF programs here
    //skel.attach()?;

    log::info!("Loaded and attached BPF objects!");

    std::thread::sleep(std::time::Duration::new(10000, 0));

    Ok(())
}

/// Extends [`libbpf_rs::Program`] with a method to attach a uprobe to a given
/// `symbol_name` within the ELF binary located at `binary_path`.
trait SymbolUprobeExt {
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: String,
        symbol_name: String,
    ) -> Result<libbpf_rs::Link>;
}

impl SymbolUprobeExt for libbpf_rs::Program {
    /// Attach a uprobe to a given `symbol_name` within the ELF binary located
    /// at `binary_path`.
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: String,
        symbol_name: String,
    ) -> Result<libbpf_rs::Link> {
        // Grab the symbol offset, if we can find it
        let func_offset = get_symbol_offset(binary_path.as_str(), symbol_name.as_str())?;

        //log::debug!(
        //    "retprobe={} pid={} binary_path={} symbol_name={}",
        //    retprobe,
        //    pid,
        //    binary_path,
        //    symbol_name
        //);

        // Use the offset we found to attach the uprobe or uretprobe
        let result = self.attach_uprobe(retprobe, pid, binary_path, func_offset)?;

        Ok(result)
    }
}
