// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::convert::{Into, TryFrom};

use anyhow::Result;
use libbpf_rs::Map;
use plain::as_bytes;
use serde::Deserialize;

use crate::bindings::policy::{bitflags, keys, values};
use crate::bpf::BpfcontainMapsMut;
use crate::policy::Policy;

use super::{LoadRule, PolicyDecision};

/// Represents a set of filesystem access flags.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileAccess(pub String);

/// An incomplete list of filesystem types from [`include/uapi/linux/magic.h`].
///
/// [`include/uapi/linux/magic.h`]: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/magic.h
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Filesystem {
    #[serde(alias = "tempfs")]
    #[serde(alias = "tmp")]
    #[serde(alias = "temp")]
    Tmpfs,
    #[serde(alias = "overlay")]
    Overlayfs,
    #[serde(alias = "ext1")]
    #[serde(alias = "ext2")]
    #[serde(alias = "ext3")]
    #[serde(alias = "ext4")]
    Ext,
    #[serde(alias = "btr")]
    Btrfs,
    #[serde(alias = "dev")]
    #[serde(alias = "devfs")]
    #[serde(alias = "devtempfs")]
    Devtmpfs,
    #[serde(alias = "proc")]
    Procfs,
    #[serde(alias = "sys")]
    Sysfs,
}

impl Filesystem {
    /// Returns the filesystem type's magic number, taken from [`include/uapi/linux/magic.h`].
    ///
    /// [`include/uapi/linux/magic.h`]: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/magic.h
    pub fn magic(&self) -> u64 {
        match self {
            Self::Tmpfs => 0x01021994,
            Self::Overlayfs => 0x794c7630,
            Self::Ext => 0xEF53,
            Self::Btrfs => 0x9123683E,
            // TODO support reiserfs?
            Self::Devtmpfs => Self::Tmpfs.magic(),
            Self::Procfs => 0x9FA0,
            Self::Sysfs => 0x62656572,
        }
    }
}

/// Represents a filesystem rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemRule {
    #[serde(rename = "type")]
    type_: Filesystem,
    access: FileAccess,
}

impl LoadRule for FilesystemRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.fs_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        // Construct the key
        let key = keys::FsPolicyKey {
            policy_id: policy.policy_id(),
            magic: self.type_.magic(),
        };

        Ok(unsafe { as_bytes(&key).into() })
    }

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let access = bitflags::FileAccess::try_from(self.access.0.as_str())?;

        let mut value = values::FilePolicyVal::default();
        match decision {
            PolicyDecision::Allow => value.allow = access.bits(),
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Deny => value.deny = access.bits(),
        }

        Ok(unsafe { as_bytes(&value).into() })
    }
}
