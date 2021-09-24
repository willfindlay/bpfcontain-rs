// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use std::{
    collections::HashSet,
    fmt::{Debug, Display},
};

use serde::{Deserialize, Serialize};

use super::PolicyIdentifier;

/// Represents an IPC access.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IpcAccess {
    pub access: IpcPermissionSet,
    pub kind: Option<IpcKindSet>,
    pub other: PolicyIdentifier,
}

/// Represents a kind of IPC.
#[derive(Hash, Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum IpcKind {
    #[serde(alias = "socket")]
    Unix,
    Pipe,
    SharedMemory,
    // Convenience aliases below this line
    Any,
}

impl Display for IpcKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

/// A wrapper around a hashset of [`IpcKind`]s.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct IpcKindSet(pub HashSet<IpcKind>);

impl Display for IpcKindSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl<'de> Deserialize<'de> for IpcKindSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HashSetOrSingle {
            HashSet(HashSet<IpcKind>),
            Single(IpcKind),
        }

        // Allows a set to be deserialized from a single item or a sequence of items.
        let hash_set = match HashSetOrSingle::deserialize(deserializer)? {
            HashSetOrSingle::HashSet(set) => set,
            HashSetOrSingle::Single(ipc) => {
                let mut s = HashSet::with_capacity(1);
                s.insert(ipc);
                s
            }
        };

        Ok(IpcKindSet(hash_set))
    }
}

impl Serialize for IpcKindSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

/// Represents an IPC permission.
#[derive(Hash, Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum IpcPermission {
    Send,
    #[serde(alias = "recv")]
    Receive,
}

impl Display for IpcPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

/// A wrapper around a hashset of [`IpcPermission`]s.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct IpcPermissionSet(HashSet<IpcPermission>);

impl From<IpcPermission> for IpcPermissionSet {
    fn from(perm: IpcPermission) -> Self {
        IpcPermissionSet(vec![perm].into_iter().collect())
    }
}

impl Display for IpcPermissionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl<'de> Deserialize<'de> for IpcPermissionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HashSetOrSingle {
            HashSet(HashSet<IpcPermission>),
            Single(IpcPermission),
        }

        // Allows a capability set to be deserialized from either a single capability or
        // a sequence of capabilities.
        let hash_set = match HashSetOrSingle::deserialize(deserializer)? {
            HashSetOrSingle::HashSet(set) => set,
            HashSetOrSingle::Single(cap) => {
                let mut s = HashSet::with_capacity(1);
                s.insert(cap);
                s
            }
        };

        Ok(IpcPermissionSet(hash_set))
    }
}

impl Serialize for IpcPermissionSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_permission_serde_test() {
        let p: IpcPermission = serde_yaml::from_str("send").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcPermission = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);

        let p: IpcPermission = serde_yaml::from_str("recv").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcPermission = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);

        serde_yaml::from_str::<IpcPermission>("[recv]").expect_err("Should fail to deserialize");
        serde_yaml::from_str::<IpcPermission>("foo").expect_err("Should fail to deserialize");
        serde_yaml::from_str::<IpcPermission>("recvaaaa").expect_err("Should fail to deserialize");
    }

    #[test]
    fn ipc_permission_set_serde_test() {
        let p: IpcPermissionSet = serde_yaml::from_str("send").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcPermissionSet = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
        assert_eq!(p.0.len(), 1);

        let p: IpcPermissionSet = serde_yaml::from_str("[send]").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcPermissionSet = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
        assert_eq!(p.0.len(), 1);

        let p: IpcPermissionSet = serde_yaml::from_str("[recv, send]").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcPermissionSet = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
        assert_eq!(p.0.len(), 2);

        serde_yaml::from_str::<IpcPermissionSet>("[send, foo]")
            .expect_err("Should fail to deserialize");
        serde_yaml::from_str::<IpcPermissionSet>("sendaaaa")
            .expect_err("Should fail to deserialize");
    }

    #[test]
    fn ipc_kind_serde_test() {
        let p: IpcKind = serde_yaml::from_str("unix").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcKind = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);

        let p: IpcKind = serde_yaml::from_str("pipe").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcKind = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
    }

    #[test]
    fn ipc_kind_set_serde_test() {
        let p: IpcKindSet = serde_yaml::from_str("[unix]").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcKindSet = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
        assert_eq!(p.0.len(), 1);

        let p: IpcKindSet = serde_yaml::from_str("[unix, pipe]").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcKindSet = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
        assert_eq!(p.0.len(), 2);
    }

    #[test]
    fn ipc_access_serde_test() {
        let p: IpcAccess =
            serde_yaml::from_str("{access: [send, recv], kind: [sysV, pipe], other: fooPolicy}")
                .expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcAccess = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);

        let p: IpcAccess =
            serde_yaml::from_str("{access: recv, other: 12}").expect("Should deserialize");
        let s = serde_yaml::to_string(&p).expect("Should serialize");
        let q: IpcAccess = serde_yaml::from_str(&s).expect("Should deserialize");
        assert_eq!(p, q);
    }
}
