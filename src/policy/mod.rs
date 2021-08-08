// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Rust side of BPFContain policy.

mod helpers;
mod rules;

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context, Error, Result};
use libbpf_rs::MapFlags;
use plain::as_bytes;
use serde::Deserialize;

use crate::bindings::policy::{keys, values};
use crate::bpf::BpfcontainSkel as Skel;
use crate::policy::rules::*;

/// A high-level representation of a BPFContain policy that has been loaded
/// from a YAML file.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy's name. Should be unique.
    /// A policy _must_ specify a name.
    pub name: String,
    /// The command associated with the policy. This will be run when the user
    /// invokes `bpfcontain-rs run </path/to/policy.yml>`.
    pub cmd: Option<String>,
    /// Whether the container should spawn in a tainted state. Otherwise, taint rules will
    /// specify when the container should become tainted. Defaults to true.
    #[serde(default = "default_true")]
    default_taint: bool,
    /// Whether the policy should complain (log) instead of deny.
    /// Defaults to false.
    #[serde(default = "default_false")]
    complain: bool,
    /// Whether the policy should be in privileged mode,
    /// granting extra capabilities when untainted.
    /// Defaults to false.
    #[serde(default = "default_false")]
    privileged: bool,
    /// The rights (allow-rules) associated with the policy.
    #[serde(default)]
    #[serde(alias = "allow")]
    rights: Vec<Rule>,
    /// The restrictions (deny-rules) associated with the policy.
    #[serde(default)]
    #[serde(alias = "deny")]
    restrictions: Vec<Rule>,
    /// The taints (taint-rules) associated with the policy.
    #[serde(default)]
    #[serde(alias = "taint")]
    taints: Vec<Rule>,
}

/// Returns false. Used for `#[serde(default = "default_false")]`
fn default_false() -> bool {
    false
}

/// Returns true. Used for `#[serde(default = "default_true")]`
fn default_true() -> bool {
    true
}

impl Policy {
    /// Construct a new policy by parsing the YAML policy file located at `path`.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        use std::fs::File;

        let mut reader = File::open(&path).context("Failed to open policy file for reading")?;

        match path.as_ref().extension().and_then(OsStr::to_str) {
            Some("toml") => {
                let mut s = String::new();
                reader.read_to_string(&mut s)?;
                toml::from_str(&s).context("Failed to parse policy file as TOML")
            }
            Some("json") => {
                serde_json::from_reader(reader).context("Failed to parse policy file as JSON")
            }
            Some("yml") | Some("yaml") => {
                serde_yaml::from_reader(reader).context("Failed to parse policy file as YAML")
            }
            Some(ext) => bail!("Unrecognized file extension {:?}", ext),
            None => bail!("No file extension specified"),
        }
    }

    /// Compute the policy id for self
    pub fn policy_id(&self) -> u64 {
        Self::policy_id_for_name(&self.name)
    }

    /// Compute the policy id for a given policy name
    pub fn policy_id_for_name(name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        hasher.finish()
    }

    /// Load the policy into the kernel
    pub fn load(&self, skel: &mut Skel) -> Result<()> {
        // Load common policy info
        self.load_common(skel)?;

        // Load rules
        self.load_rules(&self.rights, PolicyDecision::Allow, skel);
        self.load_rules(&self.restrictions, PolicyDecision::Deny, skel);
        self.load_rules(&self.taints, PolicyDecision::Taint, skel);

        Ok(())
    }

    /// Load a set of rules into the kernel
    fn load_rules(&self, rules: &[Rule], decision: PolicyDecision, skel: &mut Skel) {
        for rule in rules.iter() {
            if let Err(e) = rule.load(self, skel, decision.clone()) {
                log::warn!(
                    "Failed to load {:?} rule for policy {}: {:?}",
                    decision,
                    self.name,
                    e
                );
            }
        }
    }

    /// Load the common part of the policy into the kernel
    fn load_common(&self, skel: &mut Skel) -> Result<()> {
        type Key = keys::PolicyId;
        type Value = values::PolicyCommon;

        // Get correct map
        let mut maps = skel.maps_mut();
        let map = maps.policy_common();

        let key: Key = self.policy_id();
        let key = unsafe { as_bytes(&key) };

        let mut value = Value::default();
        value.set_default_taint(self.default_taint as u8);
        value.set_complain(self.complain as u8);
        value.set_privileged(self.privileged as u8);
        let value = unsafe { as_bytes(&value) };

        map.update(key, value, MapFlags::ANY)
            .context("Failed to update policy map")?;

        Ok(())
    }

    /// Unload the policy from the kernel
    pub fn unload(&self, skel: &mut Skel) -> Result<()> {
        // Unload common policy info
        self.unload_common(skel)?;

        // Unload rules
        self.unload_rules(&self.rights, skel);
        self.unload_rules(&self.restrictions, skel);
        self.unload_rules(&self.taints, skel);

        Ok(())
    }

    /// Unload a set of rules from the kernel
    fn unload_rules(&self, rules: &[Rule], skel: &mut Skel) {
        for rule in rules.iter() {
            if let Err(e) = rule.unload(self, skel) {
                log::warn!("Failed to unload rule for policy {}: {:?}", self.name, e);
            }
        }
    }

    /// Unload the common part of the policy from the kernel
    fn unload_common(&self, skel: &mut Skel) -> Result<()> {
        type Key = keys::PolicyId;

        // Get correct map
        let mut maps = skel.maps_mut();
        let map = maps.policy_common();

        let key: Key = self.policy_id();
        let key = unsafe { as_bytes(&key) };

        map.delete(key)
            .context("Failed to delete from policy map")?;

        Ok(())
    }

    /// Place the current process into a container that obeys this policy.
    pub fn containerize(&self) -> Result<()> {
        use bpfcontain_uprobes::do_containerize;

        let mut ret: i32 = -libc::EAGAIN;

        // Call into uprobe
        do_containerize(&mut ret as *mut i32, self.policy_id());

        match ret {
            0 => Ok(()),
            n if n == -libc::EAGAIN => bail!("Failed to call into uprobe. Is BPFContain running?"),
            n if n == -libc::ENOENT => bail!(
                "No such policy {}:{}. Has your policy been loaded?",
                self.name,
                self.policy_id()
            ),
            n if n == -libc::EINVAL => bail!("Process is already containerized or no room in map"),
            n => bail!("Unknown error: {}", n),
        }
    }
}

impl FromStr for Policy {
    type Err = Error;

    /// Construct a new policy by parsing a YAML `string`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s).context("Failed to parse policy string")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_project_path;
    use glob::glob;

    /// Make sure policy in examples/*.yml parses
    #[test]
    fn parse_examples_smoke() -> Result<()> {
        let examples_path = get_project_path("examples");
        let mut examples_str = examples_path
            .to_str()
            .expect("Failed to convert examples_path to string")
            .to_string();
        examples_str.push_str("/**/*");

        for path in glob(&examples_str)
            .expect("Failed to glob")
            .filter_map(Result::ok)
        {
            match path.extension().and_then(OsStr::to_str) {
                Some("md") => continue,
                None => continue,
                _ => {}
            };

            Policy::from_path(&path)
                .context(format!("Failed to parse policy from path {:?}", path))?;
        }

        Ok(())
    }
}
