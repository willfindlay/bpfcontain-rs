// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

mod capability;
mod device;
mod file;
mod ipc;
mod signal;

use serde::{Deserialize, Serialize};

use crate::utils::{default_false, default_true};

/// Uniquely identifies a container.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContainerIdentifier {
    #[serde(alias = "number")]
    ContainerId(u64),
}

/// Uniquely identifies a policy.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyIdentifier {
    #[serde(alias = "name")]
    PolicyName(String),
    #[serde(alias = "number")]
    PolicyId(u64),
}
