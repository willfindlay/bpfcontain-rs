// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Bindings for working with Linux namespaces.

use std::fs::read_link;
use std::path::PathBuf;

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use regex::Regex;

/// Represents all types of namespace available under Linux as of 5.9
#[derive(Copy, Clone)]
pub enum Namespace {
    Cgroup,
    Ipc,
    Mnt,
    Net,
    Pid,
    PidForChildren,
    Time,
    TimeForChildren,
    User,
    Uts,
}

impl Namespace {
    /// Translate a namespace into its canonical string name
    fn name(&self) -> &str {
        match self {
            Self::Cgroup => "cgroup",
            Self::Ipc => "ipc",
            Self::Mnt => "mnt",
            Self::Net => "net",
            Self::Pid => "pid",
            Self::PidForChildren => "pid_for_children",
            Self::Time => "time",
            Self::TimeForChildren => "time_for_children",
            Self::User => "user",
            Self::Uts => "uts",
        }
    }
}

/// Get a namespace ID for the current task
pub fn get_current_ns_id(ns: Namespace) -> Result<u32> {
    // Get corresponding name for ns
    let name = ns.name();

    // Construct /proc/self/ns/{name} path
    let mut path = PathBuf::new();
    path.push("/proc/self/ns");
    path.push(name);

    // Use readlink(2) to get namespace ID
    let link = read_link(&path).context(format!("Failed to read link {}", &path.display()))?;
    let link = link.to_str().context("Failed to convert path to string")?;

    // Compile regex exactly once
    lazy_static! {
        static ref NS_RE: Regex = Regex::new(r"[a-z]*:\[(\d*)\]").expect("Failed to compile regex");
    }

    // Parse out the namespace id
    let caps = NS_RE
        .captures(link)
        .context(format!("Failed to parse {}", link))?;
    let ns_id_str: &str = caps
        .get(1)
        .context(format!("Failed to parse id from {}", link))?
        .into();
    let ns_id: u32 = ns_id_str
        .parse()
        .context(format!("Failed to parse {} into integer", ns_id_str))?;

    Ok(ns_id)
}
