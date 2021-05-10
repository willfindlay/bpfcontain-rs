// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Defines the contents of policy files.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use glob::glob;
use libbpf_rs::MapFlags;
use pod::Pod as _;
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
    /// A policy _must_ specify a command.
    pub cmd: Option<String>,
    /// Whether the container should spawn in a tainted state. Otherwise, taint rules will
    /// specify when the container should become tainted.
    default_taint: bool,
    /// The rights (allow-rules) associated with the policy.
    #[serde(default)]
    rights: Vec<Rule>,
    /// The restrictions (deny-rules) associated with the policy.
    #[serde(default)]
    restrictions: Vec<Rule>,
    /// The taints (taint-rules) associated with the policy.
    #[serde(default)]
    taints: Vec<Rule>,
}

impl Policy {
    /// Construct a new policy by parsing the YAML policy file located at `path`.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        use std::fs::File;

        let reader = File::open(&path).context("Failed to open policy file for reading")?;

        serde_yaml::from_reader(reader).context("Failed to parse policy file")
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
        let mut maps = skel.maps();
        let map = maps.policy_common();

        let key: Key = self.policy_id();

        let mut value = Value::default();
        value.set_default_taint(self.default_taint as u8);

        map.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
            .context("Failed to update policy map")?;

        Ok(())
    }
}

impl FromStr for Policy {
    type Err = Error;

    /// Construct a new policy by parsing a YAML `string`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s).context("Failed to parse policy string")
    }
}

/// Recursively load YAML policy into the kernel from `policy_dir`.
pub fn load_policy_recursive(skel: &mut Skel, policy_dir: &str) -> Result<()> {
    log::info!("Loading policy from {}...", policy_dir);

    // Use glob to match all YAML files in the policy directory tree
    for path in glob(&format!("{}/**/*.yml", policy_dir))
        .context("Failed to glob policy directory")?
        .filter_map(Result::ok)
    {
        // Parse the policy
        let policy = match Policy::from_path(&path)
            .context(format!("Failed to parse policy for {}", path.display()))
        {
            Ok(policy) => policy,
            Err(e) => {
                log::warn!("{}", e);
                continue;
            }
        };

        // Load the policy
        match policy.load(skel).context(format!(
            "Failed to load policy {} into the kernel",
            policy.name
        )) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{}", e);
                continue;
            }
        }
    }

    log::info!("Done loading policy!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_project_path;

    /// Make sure policy in examples/*.yml parses
    #[test]
    fn parse_examples_smoke() -> Result<()> {
        let examples_path = get_project_path("examples");
        let mut examples_str = examples_path
            .to_str()
            .expect("Failed to convert examples_path to string")
            .to_string();
        examples_str.push_str("/**/*.yml");

        for path in glob::glob(&examples_str)
            .expect("Failed to glob")
            .filter_map(Result::ok)
        {
            Policy::from_path(&path)
                .context(format!("Failed to parse policy from path {:?}", path))?;
        }

        Ok(())
    }
}
