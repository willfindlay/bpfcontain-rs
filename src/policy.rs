// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use crate::{
    bpf::BpfcontainSkel,
    utils::{default_false, default_true},
};
use anyhow::{Context, Result};
use plain::as_bytes;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    hash::Hash,
    io::{Read, Write},
    path::Path,
};
use types::policy::PolicyIdentifier;

pub mod types;

mod disk;
mod rules;

pub use disk::{PolicyDiskExt, PolicyFormat};

// TODO: Move this into rules
#[derive(Hash, Debug, Serialize, Deserialize, Clone)]
pub struct Rule();

/// A serializable and deserializable BPFContain policy
#[derive(Hash, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy's ID (usually just a string name), which should be globally unique.
    #[serde(alias = "name")]
    pub id: PolicyIdentifier,
    /// The default command associated with the policy, if any.
    pub cmd: Option<String>,
    /// Whether the container should spawn in a tainted state. Otherwise, taint rules will
    /// specify when the container should become tainted. Defaults to true.
    /// Defaults to true.
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
    /// The allow rules associated with the policy. Accesses covered by these rules are
    /// always allowed, unless the access also matches a deny rule.
    #[serde(default)]
    #[serde(alias = "rights")]
    allow: Vec<Rule>,
    /// The deny rules associated with the policy. Accesses covered by these rules are
    /// always denied.
    #[serde(default)]
    #[serde(alias = "restrictions")]
    deny: Vec<Rule>,
    /// The taint rules associated with the policy. Accesses covered by these rules always
    /// taint the container, placing it into a more restrictive enforcement mode. If the
    /// container is `default_taint`, these rules do nothing.
    #[serde(default)]
    #[serde(alias = "taints")]
    taint: Vec<Rule>,
}

impl Policy {
    /// Load the policy into the kernel.
    pub fn load_kernel(&self, skel: &mut BpfcontainSkel) -> Result<()> {
        let mut maps = skel.maps_mut();
        let policy_common = maps.policy_common();

        let key = unsafe { as_bytes(&self.id.get_id()) };
        let value = todo!("FINISH ME");

        // TODO: FInish this

        Ok(())
    }
}
