// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Functionality related to BPF programs and maps.

use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use object::Object;
use object::ObjectSymbol;

use anyhow::{anyhow, Context, Result};
use glob::glob;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use log::Level;

use crate::bindings::audit;
use crate::bpf::{BpfcontainSkel, BpfcontainSkelBuilder, OpenBpfcontainSkel};
use crate::config::Settings;
use crate::log::log_error;
use crate::ns;
use crate::policy::Policy;
use crate::uprobe_ext::FindSymbolUprobeExt;
use crate::utils::bump_memlock_rlimit;

// Taken from libbpf-bootstrap rust example tracecon
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/rust/tracecon/src/main.rs#L47
// Authored by Magnus Kulke
// You can achieve a similar result for testing using objdump -tT so_path | grep fn_name
// Note get_symbol_address will return the deciaml number and objdump uses hex
fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(so_path);
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}

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
    // do_containerize
    skel.links.do_containerize = skel
        .progs_mut()
        .do_containerize()
        .attach_uprobe_addr(
            false,
            -1,
            bpfcontain_uprobes::do_containerize as *const () as usize,
        )?
        .into();

    skel.links.do_apply_policy_to_container = skel
        .progs_mut()
        .do_apply_policy_to_container()
        .attach_uprobe_addr(
            false,
            -1,
            bpfcontain_uprobes::do_apply_policy_to_container as *const () as usize,
        )?
        .into();

    // TODO: Dynamically lookup binary path
    let runc_binary_path = "/usr/bin/runc";
    let runc_func_name = "x_cgo_init";

    let runc_init_address = get_symbol_address(&runc_binary_path, &runc_func_name)?;

    skel.links.runc_x_cgo_init_enter = skel
        .progs_mut()
        .runc_x_cgo_init_enter()
        .attach_uprobe(false, -1, &runc_binary_path, runc_init_address)?
        .into();

    // TODO: Dynamically lookup binary path
    let dockerd_binary_path = "/usr/bin/dockerd";
    let dockerd_func_name = "github.com/docker/docker/container.(*State).SetRunning";

    let dockerd_running_address = get_symbol_address(&dockerd_binary_path, dockerd_func_name)?;

    skel.links.dockerd_container_running_enter = skel
        .progs_mut()
        .dockerd_container_running_enter()
        .attach_uprobe(false, -1, &dockerd_binary_path, dockerd_running_address)?
        .into();

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
