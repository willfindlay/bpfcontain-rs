// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Context, Result};
use clap::ArgMatches;

use crate::bpf;
use crate::policy::Policy;
use crate::utils::{bump_memlock_rlimit, get_symbol_offset};

/// Main entrypoint for BPF program functionality.
pub fn main(args: &ArgMatches) -> Result<()> {
    log::info!("Initializing BPF objects...");

    // Initialize the skeleton builder
    log::debug!("Initializing skeleton builder...");
    let mut skel_builder = bpf::BpfcontainSkelBuilder::default();

    // Log output from libbpf if we are -vvv
    if args.occurrences_of("v") >= 3 {
        skel_builder.obj_builder.debug(true);
    } else {
        skel_builder.obj_builder.debug(false);
    }

    // We need to bump the memlock limit to allow even the smallest of maps to
    // load properly
    log::debug!("Bumping memlock...");
    bump_memlock_rlimit()?;

    // Open eBPF objects
    log::debug!("Opening eBPF objects...");
    let mut open_skel = match skel_builder.open() {
        Ok(open_skel) => open_skel,
        Err(e) => bail!("Failed to open skeleton: {}", e),
    };

    // TODO: Set data here
    log::debug!("Setting data...");

    // Loading eBPF objects into kernel
    log::debug!("Loading eBPF objects into kernel...");
    let mut skel = match open_skel.load() {
        Ok(skel) => skel,
        Err(e) => bail!("Failed to load skeleton: {}", e),
    };

    log::debug!("Attaching BPF objects to events...");
    // Auto attach non-uprobe programs
    skel.attach()?;

    // Attach to do_containerize from /usr/lib/libbpfcontain.so
    let _link = skel.progs().do_containerize().attach_uprobe_symbol(
        false,
        -1,
        "/usr/lib/libbpfcontain.so",
        "do_containerize",
    )?;
    // Keep a reference count
    skel.links.do_containerize = Some(_link);

    log::info!("Loaded and attached BPF objects!");

    // FIXME: delete this, testing code
    let policy_str = "
        name: discord
        cmd: /bin/discord
        default: deny
        rights:
          - fs: {path: /}
          - fs: {path: /tmp}
          - file: {path: /tmp/bpfcon, access: read-only}
          - file: {path: /tmp/bpfcon, access: {flags: wx}}
          - net: {category: www, access: client-server}
          - capability: dac-override
          - capability: net-bind-service
        restrictions:
          - fs: {path: /dev}
        taints:
          - fs: {path: /}
        ";
    let policy: Policy = serde_yaml::from_str(policy_str).context("Failed to parse policy")?;
    policy.load(&mut skel).context("Failed to load policy")?;

    log::debug!("Done loading policy");

    std::thread::sleep(std::time::Duration::new(10000, 0));

    Ok(())
}

/// Extends [`libbpf_rs::Program`] with a method to attach a uprobe to a given
/// `symbol_name` within the ELF binary located at `binary_path`.
trait SymbolUprobeExt {
    /// Attach a uprobe to a given `symbol_name` within the ELF binary located
    /// at `binary_path`.
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: &str,
        symbol_name: &str,
    ) -> Result<libbpf_rs::Link>;
}

/// Extend [`libbpf_rs::Program`] with the [`SymbolUprobeExt`] trait.
impl SymbolUprobeExt for libbpf_rs::Program {
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: &str,
        symbol_name: &str,
    ) -> Result<libbpf_rs::Link> {
        // Grab the symbol offset, if we can find it
        let func_offset = get_symbol_offset(binary_path, symbol_name)?;

        log::debug!(
            "Attaching uprobe: retprobe={} pid={} binary_path={} symbol_name={}",
            retprobe,
            pid,
            binary_path,
            symbol_name
        );

        // Null terminate binary_path
        let mut binary_path = binary_path.to_string();
        binary_path.push_str("\0");

        // Use the offset we found to attach the uprobe or uretprobe
        let result = self
            .attach_uprobe(retprobe, pid, &binary_path[..], func_offset)
            .context(format!(
                "Failed to attach uprobe binary_path=`{}` symbol_name=`{}`",
                binary_path, symbol_name
            ))?;

        Ok(result)
    }
}
