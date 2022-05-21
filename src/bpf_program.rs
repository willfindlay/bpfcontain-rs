// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Functionality related to BPF programs and maps.

use std::{ffi::CString, fs, path::Path, thread::sleep, time::Duration};

use object::{Object, ObjectSymbol};

use anyhow::{anyhow, Context, Result};
use glob::glob;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use log::Level;

use crate::{
    bindings::audit,
    bpf::{BpfcontainSkel, BpfcontainSkelBuilder, OpenBpfcontainSkel},
    config::Settings,
    log::log_error,
    ns,
    policy::Policy,
    uprobe_ext::FindSymbolUprobeExt,
    utils::bump_memlock_rlimit,
};

pub struct BpfcontainContext<'a> {
    pub skel: BpfcontainSkel<'a>,
    pub ringbuf: RingBuffer,
}

impl<'a> BpfcontainContext<'a> {
    /// Open, load, and attach BPF objects, then return a new `BpfcontainContext`.
    pub fn new(config: &Settings) -> Result<Self> {
        log::debug!("Initializing BPF objects...");

        let mut builder = BpfcontainSkelBuilder::default();
        if log::log_enabled!(log::Level::Trace) {
            builder.obj_builder.debug(true);
        }

        log::debug!("Bumping memlock...");
        bump_memlock_rlimit().context("Failed bumping memlock limit")?;

        log::debug!("Opening eBPF objects...");
        let mut open_skel = builder.open().context("Failed to open skeleton")?;

        initialize_bpf_globals(&mut open_skel, config)
            .context("Failed to initialize BPF globals")?;

        log::debug!("Loading eBPF objects into kernel...");
        let mut skel = open_skel.load().context("Failed to load skeleton")?;

        log::debug!("Attaching BPF objects to events...");
        skel.attach().context("Failed to attach BPF programs")?;
        attach_uprobes(&mut skel).context("Failed to attach uprobes")?;

        log::debug!("Populating rootfs id...");
        populate_rootfs(&mut skel).context("Failed to populate rootfs id")?;

        let ringbuf = configure_ringbuf(&mut skel).context("Failed to configure ringbuf")?;

        Ok(BpfcontainContext { skel, ringbuf })
    }

    /// Main BPFContain work loop
    pub fn work_loop(&self) {
        loop {
            if let Err(e) = self.ringbuf.poll(Duration::new(1, 0)) {
                log::warn!("Failed to poll ring buffer: {}", e);
            }
            sleep(Duration::from_millis(100));
        }
    }

    /// Load a policy object into the kernel
    pub fn load_policy(&mut self, policy: &Policy) -> Result<()> {
        log::debug!("Loading policy {}...", policy.name);

        policy
            .load(&mut self.skel)
            .context(format!("Failed to load policy {}", policy.name))
    }

    /// Load policy from a file
    pub fn load_policy_from_file<P: AsRef<Path>>(&mut self, policy_path: P) -> Result<()> {
        log::info!(
            "Loading policy from file {}...",
            policy_path.as_ref().display()
        );

        let policy = Policy::from_path(&policy_path)?;
        self.load_policy(&policy)?;

        Ok(())
    }

    /// Load policy recursively from a directory
    pub fn load_policy_from_dir<P: AsRef<Path>>(&mut self, policy_dir: P) -> Result<()> {
        log::info!(
            "Loading policy recursively from {}...",
            policy_dir.as_ref().display()
        );

        // Use glob to match all YAML/TOML/JSON files in the policy directory tree
        for path in glob(&format!("{}/**/*.yml", policy_dir.as_ref().display()))
            .unwrap()
            .chain(glob(&format!("{}/**/*.yaml", policy_dir.as_ref().display())).unwrap())
            .chain(glob(&format!("{}/**/*.toml", policy_dir.as_ref().display())).unwrap())
            .chain(glob(&format!("{}/**/*.json", policy_dir.as_ref().display())).unwrap())
            .filter_map(Result::ok)
        {
            if let Err(e) = self.load_policy_from_file(path) {
                log_error(e, Some(Level::Warn));
            }
        }

        log::info!("Done loading policy!");

        Ok(())
    }

    /// Unload a policy from the kernel
    pub fn unload_policy(&mut self, policy: &Policy) -> Result<()> {
        log::debug!("Unloading policy {}...", policy.name);

        policy
            .unload(&mut self.skel)
            .context(format!("Failed to unload policy {}", policy.name))
    }
}

/// Set BPF global variables
fn initialize_bpf_globals(open_skel: &mut OpenBpfcontainSkel, config: &Settings) -> Result<()> {
    // Set own PID
    open_skel.rodata().bpfcontain_pid = std::process::id();
    // Set own mount ns id
    open_skel.rodata().host_mnt_ns_id = ns::get_current_ns_id(ns::Namespace::Mnt)?;
    // Set own pid ns id
    open_skel.rodata().host_pid_ns_id = ns::get_current_ns_id(ns::Namespace::Pid)?;
    // Set audit level
    let audit_level = config
        .bpf
        .audit_level
        .iter()
        .map(|x| audit::AuditLevel::from(x.clone()))
        .reduce(|a, b| a | b);
    open_skel.rodata().audit_level = match audit_level {
        Some(level) => level.0,
        None => audit::AuditLevel::AUDIT__NONE.0,
    };

    Ok(())
}

/// Attach uprobes to events
fn attach_uprobes(skel: &mut BpfcontainSkel) -> Result<()> {
    // TODO: Dynamically lookup binary path
    let runc_binary_path = "/usr/bin/runc";
    let runc_func_name = "x_cgo_init";

    match skel
        .progs_mut()
        .runc_x_cgo_init_enter()
        .attach_uprobe_symbol(false, -1, &runc_binary_path, runc_func_name)
    {
        Ok(link) => skel.links.runc_x_cgo_init_enter = link.into(),
        Err(e) => log::warn!(
            "Docker support will not work! runc uprobe could not be attached: {}",
            e
        ),
    }

    Ok(())
}

fn populate_rootfs(skel: &mut BpfcontainSkel) -> Result<()> {
    let rootfs_path = CString::new("/").unwrap();
    let oflags: libc::c_int = nix::libc::O_RDONLY | nix::libc::O_DIRECTORY;

    let rootfs = unsafe { nix::libc::open(rootfs_path.as_ptr() as *const libc::c_char, oflags) };
    if rootfs < 0 {
        anyhow::bail!("Failed to open rootfs mountpoint: {}", rootfs)
    }
    unsafe {
        nix::libc::ioctl(
            rootfs,
            0xDEADBEEF,
            0xDEADBEEF as *mut libc::c_void as *mut u8,
        )
    };

    log::debug!("rootfs id = {}", skel.bss().root_fs_id);
    if skel.bss().root_fs_id == 0 {
        anyhow::bail!("Failed to set rootfs id")
    }

    Ok(())
}

/// Configure ring buffers for logging
fn configure_ringbuf(skel: &mut BpfcontainSkel) -> Result<RingBuffer> {
    let mut ringbuf_builder = RingBufferBuilder::default();

    ringbuf_builder
        .add(skel.maps().__audit_buf(), audit::audit_callback)
        .context("Failed to add callback")?;

    ringbuf_builder.build().context("Failed to create ringbuf")
}
