// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::{collections::HashSet, fmt::Debug};

use anyhow::{bail, Result};
use bit_iter::BitIter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bindings::policy::bitflags::Capability as CapabilityBitflag;

/// Represents a Linux POSIX capability.
#[derive(Hash, Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum Capability {
    Chown,
    DacOverride,
    DacReadSearch,
    FOwner,
    FSetId,
    Kill,
    SetGid,
    SetUid,
    SetPCap,
    LinuxImmutable,
    NetBindService,
    NetBroadcast,
    NetAdmin,
    NetRaw,
    IpcLock,
    IpcOwner,
    SysModule,
    SysRawio,
    SysChroot,
    SysPtrace,
    SysPacct,
    SysAdmin,
    SysBoot,
    SysNice,
    SysResource,
    SysTime,
    SysTtyConfig,
    Mknod,
    Lease,
    AuditWrite,
    AuditControl,
    SetFCap,
    MacOverride,
    MacAdmin,
    SysLog,
    WakeAlarm,
    BlockSuspend,
    AuditRead,
    PerfMon,
    Bpf,
    CheckpointRestore,
    Any,
}

impl Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl TryFrom<CapabilityBitflag> for Capability {
    type Error = anyhow::Error;

    fn try_from(value: CapabilityBitflag) -> Result<Self, Self::Error> {
        Ok(match value {
            v if v == CapabilityBitflag::all() => Capability::Any,
            CapabilityBitflag::CHOWN => Self::Chown,
            CapabilityBitflag::DAC_OVERRIDE => Self::DacOverride,
            CapabilityBitflag::DAC_READ_SEARCH => Self::DacReadSearch,
            CapabilityBitflag::FOWNER => Self::FOwner,
            CapabilityBitflag::FSETID => Self::FSetId,
            CapabilityBitflag::KILL => Self::Kill,
            CapabilityBitflag::SETGID => Self::SetGid,
            CapabilityBitflag::SETUID => Self::SetUid,
            CapabilityBitflag::SETPCAP => Self::SetPCap,
            CapabilityBitflag::LINUX_IMMUTABLE => Self::LinuxImmutable,
            CapabilityBitflag::NET_BIND_SERVICE => Self::NetBindService,
            CapabilityBitflag::NET_BROADCAST => Self::NetBroadcast,
            CapabilityBitflag::NET_ADMIN => Self::NetAdmin,
            CapabilityBitflag::NET_RAW => Self::NetRaw,
            CapabilityBitflag::IPC_LOCK => Self::IpcLock,
            CapabilityBitflag::IPC_OWNER => Self::IpcOwner,
            CapabilityBitflag::SYS_MODULE => Self::SysModule,
            CapabilityBitflag::SYS_RAWIO => Self::SysRawio,
            CapabilityBitflag::SYS_CHROOT => Self::SysChroot,
            CapabilityBitflag::SYS_PTRACE => Self::SysPtrace,
            CapabilityBitflag::SYS_PACCT => Self::SysPacct,
            CapabilityBitflag::SYS_ADMIN => Self::SysAdmin,
            CapabilityBitflag::SYS_BOOT => Self::SysBoot,
            CapabilityBitflag::SYS_NICE => Self::SysNice,
            CapabilityBitflag::SYS_RESOURCE => Self::SysResource,
            CapabilityBitflag::SYS_TIME => Self::SysTime,
            CapabilityBitflag::SYS_TTY_CONFIG => Self::SysTtyConfig,
            CapabilityBitflag::MKNOD => Self::Mknod,
            CapabilityBitflag::LEASE => Self::Lease,
            CapabilityBitflag::AUDIT_WRITE => Self::AuditWrite,
            CapabilityBitflag::AUDIT_CONTROL => Self::AuditControl,
            CapabilityBitflag::SETFCAP => Self::SetFCap,
            CapabilityBitflag::MAC_OVERRIDE => Self::MacOverride,
            CapabilityBitflag::MAC_ADMIN => Self::MacAdmin,
            CapabilityBitflag::SYSLOG => Self::SysLog,
            CapabilityBitflag::WAKE_ALARM => Self::WakeAlarm,
            CapabilityBitflag::BLOCK_SUSPEND => Self::BlockSuspend,
            CapabilityBitflag::AUDIT_READ => Self::AuditRead,
            CapabilityBitflag::PERFMON => Self::PerfMon,
            CapabilityBitflag::BPF => Self::Bpf,
            CapabilityBitflag::CHECKPOINT_RESTORE => Self::CheckpointRestore,
            v => bail!("Invalid value for `Capability` {}", v.bits()),
        })
    }
}

/// A wrapper around a hashset of [`Capability`]s.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet(HashSet<Capability>);

impl Display for CapabilitySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl TryFrom<CapabilityBitflag> for CapabilitySet {
    type Error = anyhow::Error;

    fn try_from(value: CapabilityBitflag) -> Result<Self, Self::Error> {
        let mut set = HashSet::default();

        for b in BitIter::from(value.bits()).map(|b| b as u64) {
            let bit = 1 << b;
            let bitflag = CapabilityBitflag::from_bits(bit).unwrap();
            set.insert(bitflag.try_into()?);
        }

        Ok(CapabilitySet(set))
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HashSetOrSingle {
            HashSet(HashSet<Capability>),
            Single(Capability),
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

        Ok(CapabilitySet(hash_set))
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_deserialize_test() {
        // Should succeed
        let c: Capability = serde_yaml::from_str("chown").expect("Failed to deserialize");
        assert_eq!(c, Capability::Chown);

        let c: Capability = serde_yaml::from_str("dacReadSearch").expect("Failed to deserialize");
        assert_eq!(c, Capability::DacReadSearch);

        // Should fail
        serde_yaml::from_str::<Capability>("foobarqux").expect_err("Should fail to deserialize");
    }

    #[test]
    fn capability_set_deserialize_test() {
        // Should succeed
        let c: CapabilitySet = serde_yaml::from_str("chown").expect("Failed to deserialize");
        assert_eq!(c.0.len(), 1);

        let c: CapabilitySet = serde_yaml::from_str("[chown]").expect("Failed to deserialize");
        assert_eq!(c.0.len(), 1);

        let c: CapabilitySet =
            serde_yaml::from_str("[chown, sysAdmin]").expect("Failed to deserialize");
        assert_eq!(c.0.len(), 2);

        let c: CapabilitySet =
            serde_yaml::from_str("[chown, sysAdmin, chown]").expect("Failed to deserialize");
        assert_eq!(c.0.len(), 2);

        // Should fail
        serde_yaml::from_str::<CapabilitySet>("foobarqux").expect_err("Should fail to deserialize");

        serde_yaml::from_str::<CapabilitySet>("[foobarqux]")
            .expect_err("Should fail to deserialize");

        serde_yaml::from_str::<CapabilitySet>("[chown, foobarqux]")
            .expect_err("Should fail to deserialize");
    }

    #[test]
    fn capability_set_from_capability_bits_test() {
        let bitflag = CapabilityBitflag::BPF | CapabilityBitflag::KILL;
        let capset = CapabilitySet::try_from(bitflag).expect("Failed to convert bitflag to capset");
        assert_eq!(capset.0.len(), 2);
    }
}
