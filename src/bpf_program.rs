// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use glob::glob;
use std::path::Path;

use crate::bpf;
use crate::config::Settings;
use crate::policy::Policy;
use crate::utils::{bump_memlock_rlimit, get_symbol_offset};

pub use crate::bpf::BpfcontainSkelBuilder;

/// Open, load, and attach BPF programs and maps using the `builder` provided by
/// libbpf-rs.
pub fn load_bpf_program<'a>(
    builder: &'a mut bpf::BpfcontainSkelBuilder,
    debug: bool,
) -> Result<bpf::BpfcontainSkel<'a>> {
    // Log output from libbpf if we are -vv
    builder.obj_builder.debug(debug);

    // We need to bump the memlock limit to allow even the smallest of maps to
    // load properly
    log::debug!("Bumping memlock...");
    bump_memlock_rlimit()?;

    // Open eBPF objects
    log::debug!("Opening eBPF objects...");
    let open_skel = match builder.open() {
        Ok(open_skel) => open_skel,
        Err(e) => bail!("Failed to open skeleton: {}", e),
    };

    // TODO: Set data sections here
    //log::debug!("Setting data...");

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

    Ok(skel)
}

/// Load policy into the kernel from a YAML string.
pub fn load_policy_str(mut skel: &mut bpf::BpfcontainSkel, policy_str: &str) -> Result<()> {
    // Parse policy
    let policy: Policy = match serde_yaml::from_str(policy_str) {
        Ok(policy) => policy,
        Err(e) => {
            bail!("Unable to parse policy: {}", e);
        }
    };

    // Load policy
    match policy.load(&mut skel) {
        Ok(_) => {}
        Err(e) => {
            bail!("Unable to load policy: {}", e);
        }
    };

    Ok(())
}

/// Load policy into the kernel from a YAML file at `path`.
pub fn load_policy_file(mut skel: &mut bpf::BpfcontainSkel, path: &Path) -> Result<()> {
    log::info!("Loading policy {:?}...", path);

    // Open file for reading
    let reader = match std::fs::File::open(&path) {
        Ok(reader) => reader,
        Err(e) => {
            bail!("Unable to open {:?} for reading: {}", &path, e);
        }
    };

    // Parse policy
    let policy: Policy = match serde_yaml::from_reader(reader) {
        Ok(policy) => policy,
        Err(e) => {
            bail!("Unable to parse policy {:?}: {}", &path, e);
        }
    };

    // Load policy
    match policy.load(&mut skel) {
        Ok(_) => {}
        Err(e) => {
            bail!("Unable to load policy {:?}: {}", &path, e);
        }
    };

    Ok(())
}

/// Recursively load YAML policy into the kernel from `policy_dir`.
pub fn load_policy_recursive(skel: &mut bpf::BpfcontainSkel, policy_dir: &str) -> Result<()> {
    log::info!("Loading policy from {}...", policy_dir);

    // Use glob to match all YAML files in the directory tree
    for entry in
        glob(&format!("{}/**/*.yml", policy_dir)).context("Failed to glob policy directory")?
    {
        if let Ok(path) = entry {
            // We want to keep going if we fail to load a policy, but warn the
            // user
            if let Err(e) = load_policy_file(skel, &path) {
                log::warn!("Error loading policy {:?}: {}", path, e);
            }
        }
    }

    log::info!("Done loading policy!");

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
