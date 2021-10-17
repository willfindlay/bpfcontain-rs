// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use serde::{Deserialize, Serialize};

/// Uniquely identifies a container.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(untagged)]
pub enum ContainerIdentifier {
    ContainerId(u64),
}
