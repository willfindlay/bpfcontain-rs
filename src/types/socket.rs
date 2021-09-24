// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use std::{
    collections::HashSet,
    convert::TryFrom,
    fmt::{Debug, Display},
};

use anyhow::{anyhow, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bindings::raw::net_operation_t;

/// Represents a socket operation.
#[derive(Debug, Hash, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum SocketPermission {
    Create,
    Shutdown,
    Connect,
    Bind,
    Accept,
    Listen,
    Send,
    #[serde(alias = "recv")]
    Receive,
}

impl TryFrom<net_operation_t::Type> for SocketPermission {
    type Error = anyhow::Error;

    fn try_from(value: net_operation_t::Type) -> Result<Self, Self::Error> {
        Ok(match value {
            net_operation_t::BPFCON_NET_CREATE => Self::Create,
            net_operation_t::BPFCON_NET_SHUTDOWN => Self::Shutdown,
            net_operation_t::BPFCON_NET_CONNECT => Self::Connect,
            net_operation_t::BPFCON_NET_BIND => Self::Bind,
            net_operation_t::BPFCON_NET_ACCEPT => Self::Accept,
            net_operation_t::BPFCON_NET_LISTEN => Self::Listen,
            net_operation_t::BPFCON_NET_SEND => Self::Send,
            net_operation_t::BPFCON_NET_RECV => Self::Receive,
            v => bail!("Invalid value for `SocketPermission` {}", v),
        })
    }
}

impl From<SocketPermission> for net_operation_t::Type {
    fn from(value: SocketPermission) -> Self {
        use net_operation_t::*;
        match value {
            SocketPermission::Create => BPFCON_NET_CREATE,
            SocketPermission::Shutdown => BPFCON_NET_SHUTDOWN,
            SocketPermission::Connect => BPFCON_NET_CONNECT,
            SocketPermission::Bind => BPFCON_NET_BIND,
            SocketPermission::Accept => BPFCON_NET_ACCEPT,
            SocketPermission::Listen => BPFCON_NET_LISTEN,
            SocketPermission::Send => BPFCON_NET_SEND,
            SocketPermission::Receive => BPFCON_NET_RECV,
        }
    }
}

/// A wrapper around a `HashSet` of [`SocketPermission`]s.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketPermissionSet(HashSet<SocketPermission>);

impl<'de> Deserialize<'de> for SocketPermissionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HashSetOrSingle {
            HashSet(HashSet<SocketPermission>),
            Single(SocketPermission),
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

        Ok(SocketPermissionSet(hash_set))
    }
}

impl Serialize for SocketPermissionSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}
