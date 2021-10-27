// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

mod device;
mod file;
mod socket;

use std::fmt::Debug;

use anyhow::{Context, Result};
use libbpf_rs::Map;
use plain::{as_bytes, as_mut_bytes, Plain};
use serde::{Deserialize, Serialize};

use crate::{
    bpf::{BpfcontainMapsMut, BpfcontainSkel},
    policy::{types::*, Policy},
    utils::MapExt,
};

/// A BPFContain policy rule, which can be serialized, deserialized, and loaded into the
/// kernel.
#[derive(Hash, Debug, Serialize, Deserialize, Clone)]
pub enum Rule {
    File(FileAccess),
}

// Register rules using this macro. This is probably too clever by half, but it eliminates
// any code duplication without relying on the enum_dispatch crate, which doesn't work
// with associated types. (Lame!)
register_rules![File(FileAccess),];

/// A dispatch interface for [`Rule`]s.
///
/// This enables operations that load/unload a rule into/from the kernel.
pub trait RuleDispatch: Debug {
    type Key: Plain;
    type Value: Plain;

    /// Return this rule's key, which may be used to load its value into the policy map.
    fn key(&self, policy: &Policy) -> Result<Self::Key>;

    /// Return this rule's value, which may be used to loaded into the policy map.
    fn value(&self) -> Result<Self::Value>;

    /// Return the correct map corresponding to this rule.
    fn map<'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map;

    /// Load the rule into the kernel.
    fn load<'a>(&self, policy: &Policy, skel: &'a mut BpfcontainSkel) -> Result<()> {
        let key = self.key(policy).context("Failed to create the rule key")?;
        let key_bytes = unsafe { as_bytes(&key) };

        let mut value = self.value().context("Failed to create the rule value")?;
        let val_bytes = unsafe { as_mut_bytes(&mut value) };

        let mut maps = skel.maps_mut();
        let map = self.map(&mut maps);

        map.update_bitor(key_bytes, val_bytes)
            .context("Failed to add rule to the map")?;
        log::debug!(
            "Added a rule to a map. [rule={:?}, map={}]",
            &self,
            map.name()
        );

        Ok(())
    }

    /// Unload the rule from the kernel.
    fn unload<'a>(&self, policy: &Policy, skel: &'a mut BpfcontainSkel) -> Result<()> {
        let key = self.key(policy).context("Failed to create the rule key")?;
        let key_bytes = unsafe { as_bytes(&key) };

        let mut maps = skel.maps_mut();
        let map = self.map(&mut maps);

        map.delete(key_bytes)
            .context("Failed to remove rule from the map")?;
        log::debug!(
            "Deleted an existing rule from a map. [rule={:?}, map={}]",
            &self,
            map.name()
        );

        Ok(())
    }
}

#[doc(hidden)]
macro_rules! _register_rules {
    ($($kind:ident($struct_:ident),)*) => {
        impl Rule {
            pub fn load<'a>(&self, policy: &Policy, skel: &'a mut BpfcontainSkel) -> Result<()> {
                match self {
                    $(
                    Rule::$kind(rule) => rule.load(policy, skel),
                    )*
                }
                .context("Failed to load rule")
            }

            pub fn unload<'a>(&self, policy: &Policy, skel: &'a mut BpfcontainSkel) -> Result<()> {
                match self {
                    $(
                    Rule::$kind(rule) => rule.unload(policy, skel),
                    )*
                }
                .context("Failed to unload rule")
            }
        }
    };
}
// A hack to allow us to declare the macro down here and use it up north.
use _register_rules as register_rules;
