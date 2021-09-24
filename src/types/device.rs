// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use serde::{Deserialize, Serialize};

use super::file::FilePermissionSet;

/// Uniquely identifies a device on the system.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub enum DeviceIdentifier {
    #[serde(alias = "path")]
    Pathname(String),
    Numbers {
        major: u64,
        minor: Option<u64>,
    },
}

/// Access to a device.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAccess {
    #[serde(flatten)]
    pub device: DeviceIdentifier,
    pub access: FilePermissionSet,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_access_deserialize_test() {
        serde_yaml::from_str::<DeviceAccess>("{numbers: {major: 42}, access: rwx}")
            .expect("Failed to deserialize");
        serde_yaml::from_str::<DeviceAccess>("{numbers: {major: 42, minor: 24}, access: rwx}")
            .expect("Failed to deserialize");
        serde_yaml::from_str::<DeviceAccess>("{pathname: /dev/mem, access: rwx}")
            .expect("Failed to deserialize");
    }
}
