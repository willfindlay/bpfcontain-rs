// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::convert::{From, Into, TryFrom, TryInto};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use enum_dispatch::enum_dispatch;
use libbpf_rs::MapFlags;
use pod::Pod;
use serde::Deserialize;

use crate::bindings;
use crate::bpf::BpfcontainSkel as Skel;
use crate::policy::helpers::*;
use crate::policy::Policy;
use crate::utils::{path_to_dev_ino, ToBitflags};

// ============================================================================
// Rule Type and RuleControl Interface
// ============================================================================

/// A dispatch interface for [`Rule`]s.
#[enum_dispatch]
pub trait RuleControl {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()>;
}

/// Canonical rule type, dispatches to structs which implement [`RuleControl`]
/// using the `enum_dispatch` crate. Deserializable using `serde`.
#[enum_dispatch(RuleControl)]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Rule {
    // File policies
    #[serde(alias = "fs")]
    Filesystem,
    File,
    // Device policies
    Device,
    Terminal,
    DevRandom,
    DevFake,
    // Capability policy
    #[serde(alias = "cap")]
    Capability,
    // Ipc policy
    #[serde(alias = "IPC")]
    Ipc,
    // Net policy
    #[serde(alias = "net")]
    Net,
}

// ============================================================================
// File/Filesystem/Device Rules
// ============================================================================

/// Represents a set of filesystem access flags.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct FileAccess(String);

/// Convert FileAccess to bitflags
impl TryFrom<FileAccess> for bindings::policy::FileAccess {
    type Error = anyhow::Error;

    fn try_from(value: FileAccess) -> Result<Self, Self::Error> {
        // Try convenience aliases first
        match value.0.as_str() {
            "readOnly" => return Ok(Self::RO_MASK),
            "readWrite" => return Ok(Self::RW_MASK),
            "readAppend" => return Ok(Self::RA_MASK),
            "library" => return Ok(Self::LIB_MASK),
            "exec" => return Ok(Self::EXEC_MASK),
            _ => {}
        };

        let mut access = Self::default();

        // Iterate through the characters in our access flags, creating the
        // bitmask as we go.
        for c in value.0.chars() {
            // Because of weird Rust-isms, to_lowercase returns a string. We
            // only care about ASCII chars, so we will match on length-1
            // strings.
            let c_lo = &c.to_lowercase().to_string()[..];
            match c_lo {
                "x" => access |= Self::MAY_EXEC,
                "w" => access |= Self::MAY_WRITE,
                "r" => access |= Self::MAY_READ,
                "a" => access |= Self::MAY_APPEND,
                "c" => access |= Self::MAY_CREATE,
                "d" => access |= Self::MAY_DELETE,
                "n" => access |= Self::MAY_RENAME,
                "s" => access |= Self::MAY_SETATTR,
                "p" => access |= Self::MAY_CHMOD,
                "o" => access |= Self::MAY_CHOWN,
                "l" => access |= Self::MAY_LINK,
                "m" => access |= Self::MAY_EXEC_MMAP,
                "t" => access |= Self::MAY_CHDIR,
                _ => bail!("Unknown access flag {}", c),
            };
        }

        Ok(access)
    }
}

/// Represents a filesystem rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Filesystem {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl RuleControl for Filesystem {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::FsPolicyKey;
        type Value = bindings::policy::FilePolicyVal;
        type Access = bindings::policy::FileAccess;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.fs_policy();

        // Convert access into bitmask
        let access: Access = self.access.clone().try_into()?;

        // Look up device ID of the filesystem
        let (st_dev, _) = path_to_dev_ino(&PathBuf::from(&self.pathname))
            .context(format!("Failed to get information for {}", &self.pathname))?;

        // Set key
        let mut key = Key::zeroed();
        key.policy_id = policy.policy_id();
        key.device_id = st_dev as u32;
        let key = key.as_bytes();

        // Value should be old | new
        let value = {
            let mut value = Value::default();
            match decision {
                PolicyDecision::Allow => value.allow = access.bits(),
                PolicyDecision::Taint => value.taint = access.bits(),
                PolicyDecision::Deny => value.deny = access.bits(),
            }
            if let Some(old_value) = map
                .lookup(key, MapFlags::ANY)
                .context(format!("Exception during map lookup with key {:?}", key))?
            {
                let old_value =
                    Value::from_bytes(&old_value).expect("Buffer is too short or not aligned");
                value.allow |= old_value.allow;
                value.taint |= old_value.taint;
                value.deny |= old_value.deny;
            }
            value
        };

        // Update old value with new value
        map.update(key, value.as_bytes(), MapFlags::ANY)
            .context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;

        Ok(())
    }
}

/// Represents a file rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct File {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl RuleControl for File {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::FilePolicyKey;
        type Value = bindings::policy::FilePolicyVal;
        type Access = bindings::policy::FileAccess;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.file_policy();

        // Convert access into bitmask
        let access: Access = self.access.clone().try_into()?;

        // Look up device ID and inode of the file
        let (st_dev, st_ino) = path_to_dev_ino(&PathBuf::from(&self.pathname))
            .context(format!("Failed to get information for {}", &self.pathname))?;

        // Set key
        let mut key = Key::zeroed();
        key.policy_id = policy.policy_id();
        key.device_id = st_dev as u32;
        key.inode_id = st_ino;
        let key = key.as_bytes();

        // Value should be old | new
        let value = {
            let mut value = Value::default();
            match decision {
                PolicyDecision::Allow => value.allow = access.bits(),
                PolicyDecision::Taint => value.taint = access.bits(),
                PolicyDecision::Deny => value.deny = access.bits(),
            }
            if let Some(old_value) = map
                .lookup(key, MapFlags::ANY)
                .context(format!("Exception during map lookup with key {:?}", key))?
            {
                let old_value =
                    Value::from_bytes(&old_value).expect("Buffer is too short or not aligned");
                value.allow |= old_value.allow;
                value.taint |= old_value.taint;
                value.deny |= old_value.deny;
            }
            value
        };

        // Update old value with new value
        map.update(key, value.as_bytes(), MapFlags::ANY)
            .context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;

        Ok(())
    }
}

/// Helper to load a device-specific rule
fn load_device_rule(
    major: u32,
    minor: Option<u32>,
    access: FileAccess,
    policy: &Policy,
    skel: &mut Skel,
    decision: PolicyDecision,
) -> Result<()> {
    // Set correct types for rule
    type Key = bindings::policy::DevPolicyKey;
    type Value = bindings::policy::FilePolicyVal;
    type Access = bindings::policy::FileAccess;

    // Get correct map
    let mut maps = skel.maps();
    let map = maps.dev_policy();

    // Convert access into bitmask
    let access: Access = access.try_into()?;

    // Set key
    let mut key = Key::zeroed();
    key.policy_id = policy.policy_id();
    key.major = major;
    key.minor = match minor {
        Some(n) => n as i64,
        None => Key::wildcard(),
    };
    let key = key.as_bytes();

    // Value should be old | new
    let value = {
        let mut value = Value::default();
        match decision {
            PolicyDecision::Allow => value.allow = access.bits(),
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Deny => value.deny = access.bits(),
        }
        if let Some(old_value) = map
            .lookup(key, MapFlags::ANY)
            .context(format!("Exception during map lookup with key {:?}", key))?
        {
            let old_value =
                Value::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value.allow |= old_value.allow;
            value.taint |= old_value.taint;
            value.deny |= old_value.deny;
        }
        value
    };

    // Update old value with new value
    map.update(key, value.as_bytes(), MapFlags::ANY)
        .context(format!(
            "Failed to update map key={:?} value={:?}",
            key, value
        ))?;

    Ok(())
}

/// Represents a generic device access rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    major: u32,
    minor: Option<u32>,
    access: FileAccess,
}

impl RuleControl for Device {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        load_device_rule(
            self.major,
            self.minor,
            self.access.clone(),
            policy,
            skel,
            decision.clone(),
        )?;

        Ok(())
    }
}

/// Represents a terminal access rule.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Terminal;

impl RuleControl for Terminal {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        for (major, minor) in &[(136, None), (4, None)] {
            // urandom
            load_device_rule(
                *major,
                *minor,
                FileAccess("rwa".into()),
                policy,
                skel,
                decision.clone(),
            )?;
        }

        Ok(())
    }
}

/// Represents a /dev/*random access rule.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DevRandom;

impl RuleControl for DevRandom {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        for (major, minor) in &[(1, Some(8)), (1, Some(9))] {
            // urandom
            load_device_rule(
                *major,
                *minor,
                FileAccess("r".into()),
                policy,
                skel,
                decision.clone(),
            )?;
        }

        Ok(())
    }
}

/// Represents a /dev/null, /dev/full/, /dev/zero access rule.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DevFake;

impl RuleControl for DevFake {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        for (major, minor) in &[(1, Some(3)), (1, Some(5)), (1, Some(7))] {
            // urandom
            load_device_rule(
                *major,
                *minor,
                FileAccess("rwa".into()),
                policy,
                skel,
                decision.clone(),
            )?;
        }

        Ok(())
    }
}

// ============================================================================
// Capability Rules
// ============================================================================

/// Represents a capability rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Capability {
    NetBindService,
    NetRaw,
    NetBroadcast,
    DacOverride,
    DacReadSearch,
    // TODO: Others here
}

impl RuleControl for Capability {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::CapPolicyKey;
        type Value = bindings::policy::CapPolicyVal;
        type Access = bindings::policy::Capability;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.cap_policy();

        // Convert access into bitmask
        let access: Access = self.clone().into();

        // Set key
        let mut key = Key::zeroed();
        key.policy_id = policy.policy_id();
        let key = key.as_bytes();

        // Value should be old | new
        let value = {
            let mut value = Value::default();
            match decision {
                PolicyDecision::Allow => value.allow = access.bits(),
                PolicyDecision::Taint => value.taint = access.bits(),
                PolicyDecision::Deny => value.deny = access.bits(),
            }
            if let Some(old_value) = map
                .lookup(key, MapFlags::ANY)
                .context(format!("Exception during map lookup with key {:?}", key))?
            {
                let old_value =
                    Value::from_bytes(&old_value).expect("Buffer is too short or not aligned");
                value.allow |= old_value.allow;
                value.taint |= old_value.taint;
                value.deny |= old_value.deny;
            }
            value
        };

        // Update old value with new value
        map.update(key, value.as_bytes(), MapFlags::ANY)
            .context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;

        Ok(())
    }
}

impl From<Capability> for bindings::policy::Capability {
    fn from(value: Capability) -> Self {
        match value {
            Capability::NetBindService => Self::NET_BIND_SERVICE,
            Capability::NetRaw => Self::NET_RAW,
            Capability::NetBroadcast => Self::NET_BROADCAST,
            Capability::DacOverride => Self::DAC_OVERRIDE,
            Capability::DacReadSearch => Self::DAC_READ_SEARCH,
        }
    }
}

// ============================================================================
// IPC Rules
// ============================================================================

/// Represents an IPC rule, allowing IPC between two policy types if they
/// mututally grant each other access
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ipc(String);

impl RuleControl for Ipc {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::IPCPolicyKey;
        type Value = bindings::policy::IpcPolicyVal;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.cap_policy();

        // Set key
        let mut key = Key::zeroed();
        key.policy_id = policy.policy_id();
        key.other_policy_id = Policy::policy_id_for_name(&self.0);
        let key = key.as_bytes();

        // Value should be the policy decision
        let mut value = Value::default();
        value.decision = decision.to_bitflags()?.bits();

        // Update old value with new value
        map.update(key, value.as_bytes(), MapFlags::ANY)
            .context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;

        Ok(())
    }
}

// ============================================================================
// Net Rules
// ============================================================================

/// Represents network access categories
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum NetAccess {
    Client,
    Server,
    Send,
    Recv,
    Any,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Net(SingleOrVec<NetAccess>);

impl RuleControl for Net {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        todo!()
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

impl ToBitflags for PolicyDecision {
    type BitFlag = bindings::policy::PolicyDecision;

    /// Convert a [`PolicyDecision`] into a bitflag representation
    /// for loading into an eBPF map.
    fn to_bitflags(&self) -> Result<Self::BitFlag> {
        Ok(match self {
            Self::Deny => Self::BitFlag::DENY,
            Self::Allow => Self::BitFlag::ALLOW,
            Self::Taint => Self::BitFlag::TAINT,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A smoke test for deserializing filesystem rules
    #[test]
    fn test_fs_deserialize_smoke() {
        let s = "filesystem: {pathname: ez, access: pz}";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(
            rule,
            Rule::Filesystem(Filesystem {
                pathname: _,
                access: _,
            })
        ));
    }

    #[test]
    fn test_terminal_deserialize_smoke() {
        let s = "terminal:";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
    }
}
