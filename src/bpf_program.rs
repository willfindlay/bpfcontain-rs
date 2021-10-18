// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Functionality related to BPF programs and maps.

use std::convert::TryFrom;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use glob::glob;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use log::Level;
use plain::Plain;

use crate::api::ApiContext;
use crate::bindings::audit::{self, AuditData};
use crate::bpf::{BpfcontainSkel, BpfcontainSkelBuilder, OpenBpfcontainSkel};
use crate::config::Settings;
use crate::log::log_error;
use crate::ns;
use crate::policy_old::Policy;
use crate::types::AuditEvent;
use crate::uprobe_ext::FindSymbolUprobeExt;
use crate::utils::bump_memlock_rlimit;

pub struct BpfcontainContext<'a> {
    pub skel: BpfcontainSkel<'a>,
    pub ringbuf: RingBuffer,
    #[allow(dead_code)]
    // TODO: We may need to read this at some point in the future. If not, we can prefix with an underscore
    api: Arc<RwLock<ApiContext>>,
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

        log::info!("Initializing API server...");
        let api = Arc::new(RwLock::new(ApiContext::new(config)));
        log::info!("API server started successfully!");

        let ringbuf = configure_ringbuf(&mut skel, &api).context("Failed to configure ringbuf")?;

        Ok(BpfcontainContext { skel, ringbuf, api })
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
        log::info!("Loading policy {}...", policy.name);

        policy
            .load(&mut self.skel)
            .context(format!("Failed to load policy {}", policy.name))
    }

    /// Load policy from a file
    pub fn load_policy_from_file<P: AsRef<Path>>(&mut self, policy_path: P) -> Result<()> {
        log::debug!(
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
        log::info!("Unloading policy {}...", policy.name);

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

    // Set audit level based on config
    open_skel.rodata().audit_level = config
        .bpf
        .audit_level
        .iter()
        .map(|x| audit::AuditLevel::from(x.clone()))
        .reduce(|a, b| a | b)
        .map(|level| level.0)
        .unwrap_or(audit::AuditLevel::AUDIT__NONE.0);

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

    Ok(())
}

/// Configure ring buffers for logging
fn configure_ringbuf(
    skel: &mut BpfcontainSkel,
    api: &Arc<RwLock<ApiContext>>,
) -> Result<RingBuffer> {
    let mut ringbuf_builder = RingBufferBuilder::default();

    // Register a handler on audit events
    let api = api.clone();
    ringbuf_builder
        .add(skel.maps().__audit_buf(), move |data: &[u8]| {
            let data =
                AuditData::from_bytes(data).expect("Failed to convert audit data from raw bytes");

            log::info!("{}", data);

            // Convert raw audit data into an `AuditEvent`
            let event = match AuditEvent::try_from(data.to_owned()) {
                Ok(event) => event,
                Err(e) => {
                    log::error!("Failed to convert audit data to audit event: {:?}", e);
                    return -1;
                }
            };
            // ...and notify subscribers that the event has fired
            api.read().unwrap().notify_audit_subscribers(event);

            0
        })
        .context("Failed to add callback")?;

    ringbuf_builder.build().context("Failed to create ringbuf")
}
