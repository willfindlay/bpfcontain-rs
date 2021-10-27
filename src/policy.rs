// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

mod disk;
mod rules;
pub mod types;

use std::hash::Hash;

use anyhow::{Context, Result};
use libbpf_rs::MapFlags;
use plain::as_bytes;
use serde::{Deserialize, Serialize};
use types::policy::PolicyIdentifier;

use crate::{
    bindings::raw::policy_common_t,
    bpf::{BpfcontainMapsMut, BpfcontainSkel},
    utils::{default_false, default_true},
};

pub use self::disk::{PolicyDiskExt, PolicyFormat};
use self::rules::{Rule, RuleDispatch};

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

        self.load_policy_common(&mut maps)
            .context("Failed to load common part of the policy")?;

        Ok(())
    }

    pub fn load_policy_common(&self, maps: &mut BpfcontainMapsMut) -> Result<()> {
        // Compute the key from our policy id
        let key = self.id.get_id();
        let key_bytes = unsafe { as_bytes(&key) };

        // Populate the value with common policy configuration
        let mut value = policy_common_t::default();
        value.set_complain(self.complain as u8);
        value.set_privileged(self.privileged as u8);
        value.set_default_taint(self.default_taint as u8);
        let value_bytes = unsafe { as_bytes(&value) };

        // Load the common part of the policy into the kernel
        let policy_common = maps.policy_common();
        policy_common
            .update(&key_bytes, &value_bytes, MapFlags::NO_EXIST)
            .context("Failed to update policy map")?;
        log::debug!(
            "Loaded the common part of the policy into the kernel. [id={}]",
            self.id,
        );

        Ok(())
    }
}
