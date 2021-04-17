// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::ArgMatches;
use glob::glob;
use libbpf_rs::RingBufferBuilder;
use pod::Pod;

use crate::bindings;
use crate::bpf;
use crate::config::Settings;
use crate::ns;
use crate::policy::Policy;
use crate::uprobes::FindSymbolUprobeExt;
use crate::utils::bump_memlock_rlimit;

/// Main BPF program work loop.
pub fn work_loop(args: &ArgMatches, config: &Settings) -> Result<()> {
    let (mut skel, ringbuf) =
        load_bpf_program(args.occurrences_of("v") >= 2).context("Failed to load BPF program")?;

    // Load policy in `config.policy.dir`
    load_policy_recursive(&mut skel, &config.policy.dir).context("Failed to load policy")?;

    // Loop forever
    loop {
        if let Err(e) = ringbuf.poll(Duration::new(1, 0)) {
            log::warn!("Failed to poll perf buffer: {}", e);
        }
        sleep(Duration::from_millis(100));
    }
}

/// Open, load, and attach BPF programs and maps using the `builder` provided by
/// libbpf-rs.
pub fn load_bpf_program<'a>(
    debug: bool,
) -> Result<(bpf::BpfcontainSkel<'a>, libbpf_rs::RingBuffer)> {
    log::debug!("Initializing BPF objects...");

    // Initialize the skeleton builder
    log::debug!("Initializing skeleton builder...");
    let mut builder = bpf::BpfcontainSkelBuilder::default();

    // Log output from libbpf if we are -vv
    builder.obj_builder.debug(debug);

    // We need to bump the memlock limit to allow even the smallest of maps to
    // load properly
    log::debug!("Bumping memlock...");
    bump_memlock_rlimit().context("Failed bumping memlock limit")?;

    // Open eBPF objects
    log::debug!("Opening eBPF objects...");
    let mut open_skel = builder.open().context("Failed to open skeleton")?;

    // Set our own PID
    open_skel.rodata().bpfcontain_pid = std::process::id();

    // Set our own mount ns
    open_skel.rodata().host_mnt_ns_id =
        ns::get_current_ns_id(ns::Namespace::Mnt).context("Failed to find own mnt namespace id")?;

    // Set our own pid ns
    open_skel.rodata().host_pid_ns_id =
        ns::get_current_ns_id(ns::Namespace::Pid).context("Failed to find own pid namespace id")?;

    // Loading eBPF objects into kernel
    log::debug!("Loading eBPF objects into kernel...");
    let mut skel = open_skel.load().context("Failed to load skeleton")?;

    log::debug!("Attaching BPF objects to events...");
    // Auto attach non-uprobe programs
    skel.attach()?;

    // Attach to do_containerize from /usr/lib/libbpfcontain.so
    let link = skel.progs().do_containerize().attach_uprobe_symbol(
        false,
        -1,
        Path::new("/usr/lib/libbpfcontain.so"),
        "do_containerize",
    )?;
    // Keep a reference count
    skel.links.do_containerize = Some(link);

    let mut ringbuf_builder = RingBufferBuilder::default();

    ringbuf_builder
        .add(skel.maps().audit_file_buf(), audit_file)
        .context("Failed to add ringbuf")?
        .add(skel.maps().audit_cap_buf(), audit_cap)
        .context("Failed to add ringbuf")?
        .add(skel.maps().audit_net_buf(), audit_net)
        .context("Failed to add ringbuf")?
        .add(skel.maps().audit_ipc_buf(), audit_ipc)
        .context("Failed to add ringbuf")?;

    let ringbuf = ringbuf_builder
        .build()
        .context("Failed to create ringbuf manager")?;

    Ok((skel, ringbuf))
}

/// File audit events
fn audit_file(data: &[u8]) -> i32 {
    let event = bindings::audit::AuditFile::from_bytes(data).expect("Failed to copy event");

    log::info!("file {}", event);

    0
}

/// Capability audit events
fn audit_cap(data: &[u8]) -> i32 {
    let event = bindings::audit::AuditCap::from_bytes(data).expect("Failed to copy event");

    log::info!("capability {}", event);

    0
}

/// Network audit events
fn audit_net(data: &[u8]) -> i32 {
    let event = bindings::audit::AuditNet::from_bytes(data).expect("Failed to copy event");

    log::info!("network {}", event);

    0
}

/// IPC audit events
fn audit_ipc(data: &[u8]) -> i32 {
    let event = bindings::audit::AuditIpc::from_bytes(data).expect("Failed to copy event");

    log::info!("ipc {}", event);

    0
}

/// Recursively load YAML policy into the kernel from `policy_dir`.
pub fn load_policy_recursive(skel: &mut bpf::BpfcontainSkel, policy_dir: &str) -> Result<()> {
    log::info!("Loading policy from {}...", policy_dir);

    // Use glob to match all YAML files in the directory tree
    for path in glob(&format!("{}/**/*.yml", policy_dir))
        .context("Failed to glob policy directory")?
        .filter_map(Result::ok)
    {
        if let Err(e) = || -> Result<()> {
            let policy = Policy::from_path(&path).context("Failed to parse policy")?;
            policy
                .load(skel)
                .context("Failed to load policy into kernel")?;
            Ok(())
        }() {
            log::warn!("Error loading policy {}: {}", path.display(), e);
        }
    }

    log::info!("Done loading policy!");

    Ok(())
}
