// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

mod audit;
mod capability;
mod device;
mod file;
mod ipc;
mod signal;
mod socket;

use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};

use anyhow::bail;
use bit_iter::BitIter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bindings::policy::bitflags::PolicyDecision as PolicyDecisionBitflag;

pub use audit::{AuditData, AuditEvent};
pub use capability::{Capability, CapabilitySet};
pub use device::{DeviceAccess, DeviceIdentifier};
pub use file::{FileAccess, FileIdentifier, FilePermission, FilePermissionSet};
pub use ipc::{IpcAccess, IpcKind, IpcKindSet, IpcPermission, IpcPermissionSet};
pub use signal::{Signal, SignalAccess, SignalSet};

/// Uniquely identifies a container.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(untagged)]
pub enum ContainerIdentifier {
    ContainerId(u64),
}

/// Uniquely identifies a policy.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum PolicyIdentifier {
    PolicyName(String),
    PolicyId(u64),
}

/// Represents a policy decision.
#[derive(Hash, Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum PolicyDecision {
    #[serde(skip)]
    NoDecision,
    Allow,
    Deny,
    Taint,
}

impl TryFrom<PolicyDecisionBitflag> for PolicyDecision {
    type Error = anyhow::Error;

    fn try_from(value: PolicyDecisionBitflag) -> Result<Self, Self::Error> {
        Ok(match value {
            PolicyDecisionBitflag::NO_DECISION => Self::NoDecision,
            PolicyDecisionBitflag::ALLOW => Self::Allow,
            PolicyDecisionBitflag::DENY => Self::Deny,
            PolicyDecisionBitflag::TAINT => Self::Taint,
            v => bail!("Invalid value for `PolicyDecision` {}", v.bits()),
        })
    }
}

impl From<PolicyDecision> for PolicyDecisionBitflag {
    fn from(value: PolicyDecision) -> Self {
        match value {
            PolicyDecision::NoDecision => Self::NO_DECISION,
            PolicyDecision::Deny => Self::DENY,
            PolicyDecision::Allow => Self::ALLOW,
            PolicyDecision::Taint => Self::TAINT,
        }
    }
}

/// A wrapper around a `HashSet` of [`PolicyDecision`]s.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDecisionSet(HashSet<PolicyDecision>);

impl TryFrom<PolicyDecisionBitflag> for PolicyDecisionSet {
    type Error = anyhow::Error;

    fn try_from(value: PolicyDecisionBitflag) -> Result<Self, Self::Error> {
        let mut set = HashSet::default();

        for b in BitIter::from(value.bits()).map(|b| b as u32) {
            let bit = 1 << b;
            let bitflag = PolicyDecisionBitflag::from_bits(bit).unwrap();
            set.insert(bitflag.try_into()?);
        }

        Ok(PolicyDecisionSet(set))
    }
}

impl<'de> Deserialize<'de> for PolicyDecisionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HashSetOrSingle {
            HashSet(HashSet<PolicyDecision>),
            Single(PolicyDecision),
        }

        // Allows a set to be deserialized from a single item or a sequence of items.
        let hash_set = match HashSetOrSingle::deserialize(deserializer)? {
            HashSetOrSingle::HashSet(set) => set,
            HashSetOrSingle::Single(decision) => {
                let mut s = HashSet::with_capacity(1);
                s.insert(decision);
                s
            }
        };

        Ok(PolicyDecisionSet(hash_set))
    }
}

impl Serialize for PolicyDecisionSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}
