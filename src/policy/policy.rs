// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::bpf::BpfcontainSkel as Skel;
use crate::policy::rules::*;

/// Represents a default enforcement type
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum DefaultEnforcement {
    Deny,
    Allow,
}

impl Default for DefaultEnforcement {
    /// Policy should default to default-deny if not specified.
    fn default() -> Self {
        DefaultEnforcement::Deny
    }
}

/// A high-level representation of a BPFContain policy that has been loaded
/// from a YAML file.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy's name. Should be unique.
    /// A policy _must_ specify a name.
    pub name: String,
    /// The command associated with the policy. This will be run when the user
    /// invokes `bpfcontain-rs run </path/to/policy.yml>`.
    /// A policy _must_ specify a command.
    #[serde(alias = "entry")]
    pub cmd: String,
    /// Whether the policy is default-allow or default-deny. If this is not
    /// provided, we automatically assume default-deny.
    #[serde(default)]
    default: DefaultEnforcement,
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

    /// Construct a new policy by parsing a YAML `string`.
    pub fn from_str(string: &str) -> Result<Self> {
        serde_yaml::from_str(string).context("Failed to parse policy string")
    }

    pub fn policy_id(&self) -> u64 {
        Self::policy_id_for_name(&self.name)
    }

    pub fn policy_id_for_name(name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        hasher.finish()
    }

    pub fn default_taint(&self) -> bool {
        self.taints.len() == 0
    }

    pub fn default_deny(&self) -> bool {
        self.default == DefaultEnforcement::Deny
    }

    pub fn load(&self, skel: &mut Skel) -> Result<()> {
        // Load rights
        for rule in self.rights.iter() {
            // TODO: Handle errors gracefully
            rule.load(self, skel, PolicyDecision::Allow)
                .context("Failed to load rule")?;
        }

        // Load restrictions
        for rule in self.restrictions.iter() {
            // TODO: Handle errors gracefully
            rule.load(self, skel, PolicyDecision::Deny)
                .context("Failed to load rule")?;
        }

        // Load taints
        for rule in self.taints.iter() {
            // TODO: Handle errors gracefully
            rule.load(self, skel, PolicyDecision::Taint)
                .context("Failed to load rule")?;
        }

        Ok(())
    }
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
            let p = Policy::from_path(&path)
                .context(format!("Failed to parse policy from path {:?}", path))?;
            println!("{:#?}", p);
        }

        Ok(())
    }
}
