// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Definitions for policy rules and their translations into eBPF maps. Uses the
//! `enum_dispatch` crate.

use std::convert::{From, Into, TryFrom, TryInto};
use std::path::PathBuf;

use anyhow::{Context, Result};
use enum_dispatch::enum_dispatch;
use glob::glob;
use libbpf_rs::Map;
use libbpf_rs::MapFlags;
use plain::as_bytes;
use serde::Deserialize;

use crate::bindings::policy::{bitflags, keys, values};
use crate::bpf::{BpfcontainMapsMut, BpfcontainSkel as Skel};
use crate::policy::helpers::*;
use crate::policy::Policy;
use crate::utils::path_to_dev_ino;

// ============================================================================
// Rule Type and LoadRule Interface
// ============================================================================

/// A dispatch interface for [`Rule`]s.
#[enum_dispatch]
pub trait LoadRule {
    /// Get the POD representation of the map key for this rule.
    fn key(&self, policy: &Policy) -> Result<Vec<u8>>;

    /// Get the POD representation of the map value for this rule.
    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>>;

    /// Get a mutable reference to the eBPF map corresponding with this rule.
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map;

    /// Lookup existing value and return it as POD if it exists.
    fn lookup_existing_value<'a: 'a>(
        &self,
        key: &[u8],
        maps: &'a mut BpfcontainMapsMut,
    ) -> Result<Option<Vec<u8>>> {
        let map = self.map(maps);
        Ok(map.lookup(key, MapFlags::ANY)?)
    }

    /// Load this rule into the kernel.
    fn load<'a: 'a>(
        &self,
        policy: &Policy,
        skel: &'a mut Skel,
        decision: PolicyDecision,
    ) -> Result<()> {
        let key = &self.key(policy).context("Failed to create map key")?;
        let value = &mut self
            .value(&decision)
            .context("Failed to create map value")?;

        // We don't want to _replace_ the existing value. Rather, we want to _extend_ it.
        // For BPFContain policy, this means doing a bitwise OR with the existing value
        // and populating the map with the result. This is an ugly hack to do just that
        // by taking the bitwise OR over each byte of the POD data.
        //
        // This is probably code smell, but there isn't much we can do about this for now,
        // until we can figure out a way to support the actual Key, Value types over an
        // enum_dispatch interface.
        let mut maps = skel.maps_mut();
        if let Some(existing) = self.lookup_existing_value(key, &mut maps)? {
            for (old, new) in existing.iter().zip(value.iter_mut()) {
                *new |= *old;
            }
        }

        // Update the actual map value.
        let map = self.map(&mut maps);
        map.update(key, value, MapFlags::ANY)
            .context("Failed to update map value")?;

        Ok(())
    }

    /// Unload this rule from the kernel.
    fn unload<'a: 'a>(&self, policy: &Policy, skel: &'a mut Skel) -> Result<()> {
        let key = &self.key(policy).context("Failed to create map key")?;

        let mut maps = skel.maps_mut();
        let map = self.map(&mut maps);

        // Remove the value corresponding with the key.
        map.delete(key).context("Failed to delete map value")?;

        Ok(())
    }
}

/// Canonical rule type, dispatches to structs which implement [`LoadRule`]
/// using the `enum_dispatch` crate. Deserializable using `serde`.
#[enum_dispatch(LoadRule)]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Rule {
    // File policies
    #[serde(alias = "fs")]
    Filesystem(FilesystemRule),
    File(GlobRule),
    // Device policies
    #[serde(alias = "numberedDev")]
    NumberedDevice(NumberedDeviceRule),
    #[serde(alias = "dev")]
    Device(DeviceRule),
    // Capability policy
    #[serde(alias = "cap")]
    Capability(CapabilityRule),
    // Ipc policy
    #[serde(alias = "IPC")]
    Ipc(IpcRule),
    // Net policy
    #[serde(alias = "network")]
    Net(NetRule),
    // Signal policy
    #[serde(alias = "sig")]
    Signal(SignalRule),
}

// ============================================================================
// File/Filesystem/Device Rules
// ============================================================================

/// Represents a set of filesystem access flags.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct FileAccess(String);

/// Represents a filesystem rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemRule {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl LoadRule for FilesystemRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.fs_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        // Look up device ID of the filesystem
        let (st_dev, _) = path_to_dev_ino(&PathBuf::from(&self.pathname))
            .context(format!("Failed to get information for {}", &self.pathname))?;

        // Construct the key
        let key = keys::FsPolicyKey {
            policy_id: policy.policy_id(),
            device_id: st_dev as u32,
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

/// Represents a file rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileRule {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl LoadRule for FileRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.file_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        // Look up device ID of the filesystem
        let (st_dev, st_ino) = path_to_dev_ino(&PathBuf::from(&self.pathname))
            .context(format!("Failed to get information for {}", &self.pathname))?;

        // Construct the key
        let key = keys::FilePolicyKey {
            policy_id: policy.policy_id(),
            device_id: st_dev as u32,
            inode_id: st_ino,
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

/// Represents a globbing pattern for file rules
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GlobRule {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl LoadRule for GlobRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.file_policy()
    }

    fn key(&self, _policy: &Policy) -> Result<Vec<u8>> {
        panic!("`GlobRule`s defer to `FileRule`s for loading/unloading.");
    }

    fn value(&self, _decision: &PolicyDecision) -> Result<Vec<u8>> {
        panic!("`GlobRule`s defer to `FileRule`s for loading/unloading.");
    }
    /// This is a reimplementation of LoadRule::load(), the only difference being that we
    /// want to unload _multiple_ key, value pairs from the kernel.
    fn unload<'a: 'a>(&self, policy: &Policy, skel: &'a mut Skel) -> Result<()> {
        for path in glob(&self.pathname)
            .context("Failed to glob")?
            .filter_map(Result::ok)
        {
            let file_rule = FileRule {
                pathname: path.to_string_lossy().to_string(),
                access: self.access.clone(),
            };

            file_rule.unload(policy, skel)?;
        }

        Ok(())
    }

    /// This is a reimplementation of LoadRule::load(), the only difference being that we
    /// want to load _multiple_ key, value pairs into the kernel.
    fn load<'a: 'a>(
        &self,
        policy: &Policy,
        skel: &'a mut Skel,
        decision: PolicyDecision,
    ) -> Result<()> {
        for path in glob(&self.pathname)
            .context("Failed to glob")?
            .filter_map(Result::ok)
        {
            let file_rule = FileRule {
                pathname: path.to_string_lossy().to_string(),
                access: self.access.clone(),
            };

            log::trace!("loading file rule {:?}", file_rule);
            file_rule.load(policy, skel, decision.clone())?;
        }

        Ok(())
    }
}

/// Represents a generic device access rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NumberedDeviceRule {
    major: u32,
    minor: Option<u32>,
    access: FileAccess,
}

impl LoadRule for NumberedDeviceRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.dev_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        let key = keys::DevPolicyKey {
            policy_id: policy.policy_id(),
            major: self.major,
            minor: match self.minor {
                Some(minor) => minor as i64,
                None => keys::DevPolicyKey::wildcard(),
            },
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

/// Represents a high-level device class which is converted into an access vector along
/// with one or more keys.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Device {
    #[serde(alias = "tty")]
    Terminal,
    Null,
    Random,
}

impl Device {
    /// Get the access vector that should be associated with this device.
    pub fn access(&self) -> bitflags::FileAccess {
        match self {
            Device::Terminal => "rwai".try_into().unwrap(),
            Device::Null => "rwa".try_into().unwrap(),
            Device::Random => "r".try_into().unwrap(),
        }
    }

    /// Get the major and minor numbers associated with this device type.
    /// A minor number of None implies a wildcard (matching all minor numbers).
    pub fn device_numbers(&self) -> Vec<(u32, Option<u32>)> {
        match self {
            Device::Terminal => vec![(136, None), (4, None), (5, None)],
            Device::Null => vec![(1, Some(3)), (1, Some(5)), (1, Some(7))],
            Device::Random => vec![(1, Some(8)), (1, Some(9))],
        }
    }
}

/// Represents a high-level device access rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRule(Device);

impl DeviceRule {}

impl LoadRule for DeviceRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.dev_policy()
    }

    fn key(&self, _policy: &Policy) -> Result<Vec<u8>> {
        panic!("`DeviceRule`s have multiple keys and thus require special handling.");
    }

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let access = self.0.access();

        let mut value = values::FilePolicyVal::default();
        match decision {
            PolicyDecision::Allow => value.allow = access.bits(),
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Deny => value.deny = access.bits(),
        }

        Ok(unsafe { as_bytes(&value).into() })
    }

    /// This is a reimplementation of LoadRule::load(), the only difference being that we
    /// want to unload _multiple_ key, value pairs from the kernel.
    fn unload<'a: 'a>(&self, policy: &Policy, skel: &'a mut Skel) -> Result<()> {
        let mut maps = skel.maps_mut();
        let map = self.map(&mut maps);

        for (major, minor) in self.0.device_numbers() {
            let key = keys::DevPolicyKey {
                policy_id: policy.policy_id(),
                major,
                minor: match minor {
                    Some(minor) => minor as i64,
                    None => keys::DevPolicyKey::wildcard(),
                },
            };
            let key = unsafe { as_bytes(&key) };

            map.delete(key).context("Failed to delete map value")?;
        }

        Ok(())
    }

    /// This is a reimplementation of LoadRule::load(), the only difference being that we
    /// want to load _multiple_ key, value pairs into the kernel.
    fn load<'a: 'a>(
        &self,
        policy: &Policy,
        skel: &'a mut Skel,
        decision: PolicyDecision,
    ) -> Result<()> {
        let mut maps = skel.maps_mut();

        let value = &mut self.value(&decision)?;

        for (major, minor) in self.0.device_numbers() {
            let key = keys::DevPolicyKey {
                policy_id: policy.policy_id(),
                major,
                minor: if let Some(minor) = minor {
                    minor as i64
                } else {
                    keys::DevPolicyKey::wildcard()
                },
            };
            let key = unsafe { as_bytes(&key) };

            // We don't want to _replace_ the existing value. Rather, we want to _extend_ it.
            // For BPFContain policy, this means doing a bitwise OR with the existing value
            // and populating the map with the result. This is an ugly hack to do just that
            // by taking the bitwise OR over each byte of the POD data.
            //
            // This is probably code smell, but there isn't much we can do about this for now,
            // until we can figure out a way to support the actual Key, Value types over an
            // enum_dispatch interface.
            if let Some(existing) = self.lookup_existing_value(key, &mut maps)? {
                for (old, new) in existing.iter().zip(value.iter_mut()) {
                    *new |= *old;
                }
            }

            let map = self.map(&mut maps);
            map.update(key, value, MapFlags::ANY)
                .context("Failed to update map value")?;
        }

        Ok(())
    }
}

// ============================================================================
// Capability Rules
// ============================================================================

/// Represents a capability.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Capability {
    Chown,
    DacOverride,
    DacReadSearch,
    FOwner,
    #[serde(alias = "fSetID")]
    FSetId,
    Kill,
    #[serde(alias = "setGID")]
    SetGid,
    #[serde(alias = "setUID")]
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
    #[serde(alias = "sysTTYConfig")]
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
    #[serde(alias = "BPF")]
    Bpf,
    CheckpointRestore,
    Any,
}

impl From<Capability> for bitflags::Capability {
    fn from(value: Capability) -> Self {
        match value {
            Capability::Chown => Self::CHOWN,
            Capability::DacOverride => Self::DAC_OVERRIDE,
            Capability::DacReadSearch => Self::DAC_READ_SEARCH,
            Capability::FOwner => Self::FOWNER,
            Capability::FSetId => Self::FSETID,
            Capability::Kill => Self::KILL,
            Capability::SetGid => Self::SETGID,
            Capability::SetUid => Self::SETUID,
            Capability::SetPCap => Self::SETPCAP,
            Capability::LinuxImmutable => Self::LINUX_IMMUTABLE,
            Capability::NetBindService => Self::NET_BIND_SERVICE,
            Capability::NetBroadcast => Self::NET_BROADCAST,
            Capability::NetAdmin => Self::NET_ADMIN,
            Capability::NetRaw => Self::NET_RAW,
            Capability::IpcLock => Self::IPC_LOCK,
            Capability::IpcOwner => Self::IPC_OWNER,
            Capability::SysModule => Self::SYS_MODULE,
            Capability::SysRawio => Self::SYS_RAWIO,
            Capability::SysChroot => Self::SYS_CHROOT,
            Capability::SysPtrace => Self::SYS_PTRACE,
            Capability::SysPacct => Self::SYS_PACCT,
            Capability::SysAdmin => Self::SYS_ADMIN,
            Capability::SysBoot => Self::SYS_BOOT,
            Capability::SysNice => Self::SYS_NICE,
            Capability::SysResource => Self::SYS_RESOURCE,
            Capability::SysTime => Self::SYS_TIME,
            Capability::SysTtyConfig => Self::SYS_TTY_CONFIG,
            Capability::Mknod => Self::MKNOD,
            Capability::Lease => Self::LEASE,
            Capability::AuditWrite => Self::AUDIT_WRITE,
            Capability::AuditControl => Self::AUDIT_CONTROL,
            Capability::SetFCap => Self::SETFCAP,
            Capability::MacOverride => Self::MAC_OVERRIDE,
            Capability::MacAdmin => Self::MAC_ADMIN,
            Capability::SysLog => Self::SYSLOG,
            Capability::WakeAlarm => Self::WAKE_ALARM,
            Capability::BlockSuspend => Self::BLOCK_SUSPEND,
            Capability::AuditRead => Self::AUDIT_READ,
            Capability::PerfMon => Self::PERFMON,
            Capability::Bpf => Self::BPF,
            Capability::CheckpointRestore => Self::CHECKPOINT_RESTORE,
            Capability::Any => Self::all(),
        }
    }
}

/// Represents a capability rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRule(SingleOrVec<Capability>);

impl LoadRule for CapabilityRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.cap_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        let key = keys::CapPolicyKey {
            policy_id: policy.policy_id(),
        };

        Ok(unsafe { as_bytes(&key).into() })
    }

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let capvec: Vec<_> = self.0.clone().into();
        let access: bitflags::Capability = capvec
            .iter()
            .fold(bitflags::Capability::default(), |v1, v2| {
                v1 | bitflags::Capability::from(v2.clone())
            });

        let mut value = values::CapPolicyVal::default();
        match decision {
            PolicyDecision::Allow => value.allow = access.bits(),
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Deny => value.deny = access.bits(),
        }

        Ok(unsafe { as_bytes(&value).into() })
    }
}

// ============================================================================
// IPC Rules
// ============================================================================

/// Represents an IPC rule, allowing IPC between two policy types if they
/// mututally grant each other access.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IpcRule(String);

impl LoadRule for IpcRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.ipc_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        let key = keys::IpcPolicyKey {
            policy_id: policy.policy_id(),
            other_policy_id: Policy::policy_id_for_name(&self.0),
        };

        Ok(unsafe { as_bytes(&key).into() })
    }

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let value = values::IpcPolicyVal {
            decision: bitflags::PolicyDecision::from(decision.clone()).bits(),
        };

        Ok(unsafe { as_bytes(&value).into() })
    }
}

// ============================================================================
// Signal Rules
// ============================================================================

/// Represents a signal type
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Signal {
    SigChk,
    SigHup,
    SigInt,
    SigQuit,
    SigIll,
    SigTrap,
    SigAbrt,
    SigBus,
    SigFpe,
    SigKill,
    SigUsr1,
    SigSegv,
    SigUsr2,
    SigPipe,
    SigAlrm,
    SigTerm,
    SigStkFlt,
    SigChld,
    SigCont,
    SigStop,
    SigTstp,
    SigTtin,
    SigTtou,
    SigUrg,
    SigXcpu,
    SigXfsz,
    SigVtAlrm,
    SigProf,
    SigWinch,
    SigIo,
    SigPwr,
    SigSys,
    // Convenience aliases below this line
    Any,
    Check,
    Fatal,
    Stop,
    SuperFatal,
    SuperStop,
}

impl From<Signal> for bitflags::Signal {
    fn from(sig: Signal) -> Self {
        match sig {
            Signal::SigChk => Self::SIGCHK,
            Signal::SigHup => Self::SIGHUP,
            Signal::SigInt => Self::SIGINT,
            Signal::SigQuit => Self::SIGQUIT,
            Signal::SigIll => Self::SIGILL,
            Signal::SigTrap => Self::SIGTRAP,
            Signal::SigAbrt => Self::SIGABRT,
            Signal::SigBus => Self::SIGBUS,
            Signal::SigFpe => Self::SIGFPE,
            Signal::SigKill => Self::SIGKILL,
            Signal::SigUsr1 => Self::SIGUSR1,
            Signal::SigSegv => Self::SIGSEGV,
            Signal::SigUsr2 => Self::SIGUSR2,
            Signal::SigPipe => Self::SIGPIPE,
            Signal::SigAlrm => Self::SIGALRM,
            Signal::SigTerm => Self::SIGTERM,
            Signal::SigStkFlt => Self::SIGSTKFLT,
            Signal::SigChld => Self::SIGCHLD,
            Signal::SigCont => Self::SIGCONT,
            Signal::SigStop => Self::SIGSTOP,
            Signal::SigTstp => Self::SIGTSTP,
            Signal::SigTtin => Self::SIGTTIN,
            Signal::SigTtou => Self::SIGTTOU,
            Signal::SigUrg => Self::SIGURG,
            Signal::SigXcpu => Self::SIGXCPU,
            Signal::SigXfsz => Self::SIGXFSZ,
            Signal::SigVtAlrm => Self::SIGVTALRM,
            Signal::SigProf => Self::SIGPROF,
            Signal::SigWinch => Self::SIGWINCH,
            Signal::SigIo => Self::SIGIO,
            Signal::SigPwr => Self::SIGPWR,
            Signal::SigSys => Self::SIGSYS,
            Signal::Any => Self::all(),
            Signal::Check => Self::SIGCHK,
            Signal::Fatal => Self::SIGTERM | Self::SIGINT,
            Signal::Stop => Self::SIGSTOP,
            Signal::SuperFatal => bitflags::Signal::from(Signal::Fatal) | Self::SIGKILL,
            Signal::SuperStop => bitflags::Signal::from(Signal::Stop) | Self::SIGTSTP,
        }
    }
}

/// Represents a signal rule, allowing a container to send signals to other containers
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignalRule {
    #[serde(alias = "receiver")]
    to: String,
    #[serde(alias = "signal")]
    signals: SingleOrVec<Signal>,
}

impl LoadRule for SignalRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.signal_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        let key = keys::SignalPolicyKey {
            sender_id: policy.policy_id(),
            receiver_id: Policy::policy_id_for_name(&self.to),
        };

        Ok(unsafe { as_bytes(&key).into() })
    }

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let mut value = values::SignalPolicyVal::default();

        let signal_mask = self
            .signals
            .clone()
            .into_iter()
            .map(bitflags::Signal::from)
            .reduce(|a, b| a | b)
            .unwrap();

        match decision {
            PolicyDecision::Allow => value.allow = signal_mask.bits(),
            PolicyDecision::Deny => value.deny = signal_mask.bits(),
            PolicyDecision::Taint => value.taint = signal_mask.bits(),
        };

        Ok(unsafe { as_bytes(&value).into() })
    }
}

// ============================================================================
// Net Rules
// ============================================================================

/// Represents network access categories.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum NetAccess {
    Client,
    Server,
    Send,
    Recv,
    Any,
}

impl From<NetAccess> for bitflags::NetOperation {
    fn from(value: NetAccess) -> Self {
        match value {
            NetAccess::Client => Self::MASK_CLIENT,
            NetAccess::Server => Self::MASK_SERVER,
            NetAccess::Send => Self::MASK_SEND,
            NetAccess::Recv => Self::MASK_RECV,
            NetAccess::Any => Self::all(),
        }
    }
}

/// Represents a network access rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetRule(SingleOrVec<NetAccess>);

impl LoadRule for NetRule {
    fn map<'a: 'a>(&self, maps: &'a mut BpfcontainMapsMut) -> &'a mut Map {
        maps.net_policy()
    }

    fn key(&self, policy: &Policy) -> Result<Vec<u8>> {
        let key = keys::NetPolicyKey {
            policy_id: policy.policy_id(),
        };

        Ok(unsafe { as_bytes(&key).into() })
    }

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let netvec: Vec<_> = self.0.clone().into();
        let access: bitflags::NetOperation = netvec
            .iter()
            .fold(bitflags::NetOperation::default(), |v1, v2| {
                v1 | bitflags::NetOperation::from(v2.clone())
            });

        let mut value = values::NetPolicyVal::default();
        match decision {
            PolicyDecision::Allow => value.allow = access.bits(),
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Deny => value.deny = access.bits(),
        }

        Ok(unsafe { as_bytes(&value).into() })
    }
}

// ============================================================================
// Policy Decisions
// ============================================================================

/// Represents a policy decision.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PolicyDecision {
    Deny,
    Allow,
    Taint,
}

impl From<PolicyDecision> for bitflags::PolicyDecision {
    fn from(value: PolicyDecision) -> Self {
        match value {
            PolicyDecision::Deny => Self::DENY,
            PolicyDecision::Allow => Self::ALLOW,
            PolicyDecision::Taint => Self::TAINT,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A smoke test for deserializing filesystem rules.
    #[test]
    fn test_fs_deserialize_smoke() {
        let s = "filesystem: {pathname: /tmp, access: readOnly}";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Filesystem(_)));
    }

    /// A smoke test for deserializing file rules.
    #[test]
    fn test_file_deserialize_smoke() {
        let s = "file: {pathname: /foo/bar, access: readWrite}";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::File(_)))
    }

    /// A smoke test for deserializing numbered device rules.
    #[test]
    fn test_numbered_dev_deserialize_smoke() {
        let s = "numberedDevice: {major: 136, minor: 2, access: readOnly}";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::NumberedDevice(_)))
    }

    /// A smoke test for deserializing normal device rules.
    #[test]
    fn test_dev_deserialize_smoke() {
        let s = "device: terminal";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Device(_)));

        let s = "device: null";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Device(_)));

        let s = "device: random";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Device(_)))
    }

    ///// A smoke test for deserializing terminal rules.
    //#[test]
    //fn test_terminal_deserialize_smoke() {
    //    let s = "terminal:";
    //    let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
    //    assert!(matches!(rule, Rule::Terminal(_)))
    //}

    ///// A smoke test for deserializing devrandom rules.
    //#[test]
    //fn test_devrandom_deserialize_smoke() {
    //    let s = "devRandom:";
    //    let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
    //    assert!(matches!(rule, Rule::DevRandom(_)))
    //}

    ///// A smoke test for deserializing devfake rules.
    //#[test]
    //fn test_devfake_deserialize_smoke() {
    //    let s = "devFake:";
    //    let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
    //    assert!(matches!(rule, Rule::DevFake(_)))
    //}

    /// A smoke test for deserializing capability rules.
    #[test]
    fn test_capability_deserialize_smoke() {
        let s = "capability: dacOverride";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Capability(_)))
    }

    /// A smoke test for deserializing ipc rules.
    #[test]
    fn test_ipc_deserialize_smoke() {
        let s = "ipc: foobar";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Ipc(_)))
    }

    /// A smoke test for deserializing net rules.
    #[test]
    fn test_net_deserialize_smoke() {
        let s = "net: [client, send]";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Net(_)))
    }

    /// A smoke test for deserializing signal rules.
    #[test]
    fn test_signal_deserialize_smoke() {
        let s = "signal: {to: foobar, signals: [sigUsr1, sigTerm, sigKill, sigUsr2]}";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Signal(_)))
    }
}
