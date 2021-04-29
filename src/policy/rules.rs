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

use anyhow::{bail, Context, Result};
use enum_dispatch::enum_dispatch;
use libbpf_rs::MapFlags;
use pod::Pod;
use serde::Deserialize;

use crate::bindings;
use crate::bpf::BpfcontainSkel as Skel;
use crate::policy::helpers::*;
use crate::policy::Policy;
use crate::utils::path_to_dev_ino;

// ============================================================================
// Rule Type and LoadRule Interface
// ============================================================================

/// A dispatch interface for [`Rule`]s.
#[enum_dispatch]
pub trait LoadRule {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()>;
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
    File(FileRule),
    // Device policies
    Device(DeviceRule),
    Terminal(TerminalRule),
    DevRandom(DevRandomRule),
    DevFake(DevFakeRule),
    // Capability policy
    #[serde(alias = "cap")]
    Capability(CapabilityRule),
    // Ipc policy
    #[serde(alias = "IPC")]
    Ipc(IpcRule),
    // Net policy
    #[serde(alias = "net")]
    Net(NetRule),
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
            "readOnly" => return Ok(Self::MAY_READ),
            "readWrite" => return Ok(Self::MAY_READ | Self::MAY_WRITE | Self::MAY_APPEND),
            "readAppend" => return Ok(Self::MAY_READ | Self::MAY_APPEND),
            "library" => return Ok(Self::MAY_READ | Self::MAY_EXEC_MMAP),
            "exec" => return Ok(Self::MAY_READ | Self::MAY_EXEC),
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
                "r" => access |= Self::MAY_READ,
                "w" => access |= Self::MAY_WRITE,
                "x" => access |= Self::MAY_EXEC,
                "a" => access |= Self::MAY_APPEND,
                "d" => access |= Self::MAY_DELETE,
                "c" => access |= Self::MAY_CHMOD,
                "l" => access |= Self::MAY_LINK,
                "m" => access |= Self::MAY_EXEC_MMAP,
                _ => bail!("Unknown access flag {}", c),
            };
        }

        Ok(access)
    }
}

/// Represents a filesystem rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemRule {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl LoadRule for FilesystemRule {
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
pub struct FileRule {
    #[serde(alias = "path")]
    pathname: String,
    access: FileAccess,
}

impl LoadRule for FileRule {
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
pub struct DeviceRule {
    major: u32,
    minor: Option<u32>,
    access: FileAccess,
}

impl LoadRule for DeviceRule {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        load_device_rule(
            self.major,
            self.minor,
            self.access.clone(),
            policy,
            skel,
            decision,
        )?;

        Ok(())
    }
}

/// Represents a terminal access rule.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TerminalRule;

impl LoadRule for TerminalRule {
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
pub struct DevRandomRule;

impl LoadRule for DevRandomRule {
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
pub struct DevFakeRule;

impl LoadRule for DevFakeRule {
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

/// Represents a capability.
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

/// Represents a capability rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRule(SingleOrVec<Capability>);

impl LoadRule for CapabilityRule {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::CapPolicyKey;
        type Value = bindings::policy::CapPolicyVal;
        type Access = bindings::policy::Capability;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.cap_policy();

        // Convert access into bitmask
        let vec: Vec<Capability> = self.0.clone().into();
        let access: Access = vec
            .iter()
            .fold(Access::default(), |v1, v2| v1 | Access::from(v2.clone()));

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

// ============================================================================
// IPC Rules
// ============================================================================

/// Represents an IPC rule, allowing IPC between two policy types if they
/// mututally grant each other access.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IpcRule(String);

impl LoadRule for IpcRule {
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::IpcPolicyKey;
        type Value = bindings::policy::IpcPolicyVal;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.ipc_policy();

        // Set key
        let mut key = Key::zeroed();
        key.policy_id = policy.policy_id();
        key.other_policy_id = Policy::policy_id_for_name(&self.0);
        let key = key.as_bytes();

        // Value should be the policy decision
        let mut value = Value::default();
        value.decision = bindings::policy::PolicyDecision::from(decision).bits();

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

impl From<NetAccess> for bindings::policy::NetOperation {
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
    fn load(&self, policy: &Policy, skel: &mut Skel, decision: PolicyDecision) -> Result<()> {
        // Set correct types for rule
        type Key = bindings::policy::NetPolicyKey;
        type Value = bindings::policy::NetPolicyVal;
        type Access = bindings::policy::NetOperation;

        // Get correct map
        let mut maps = skel.maps();
        let map = maps.net_policy();

        // Convert access into bitmask
        let vec: Vec<NetAccess> = self.0.clone().into();
        let access: Access = vec
            .iter()
            .fold(Access::default(), |v1, v2| v1 | Access::from(v2.clone()));

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

impl From<PolicyDecision> for bindings::policy::PolicyDecision {
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

    /// A smoke test for deserializing device rules.
    #[test]
    fn test_dev_deserialize_smoke() {
        let s = "device: {major: 136, minor: 2, access: readOnly}";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Device(_)))
    }

    /// A smoke test for deserializing terminal rules.
    #[test]
    fn test_terminal_deserialize_smoke() {
        let s = "terminal:";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::Terminal(_)))
    }

    /// A smoke test for deserializing devrandom rules.
    #[test]
    fn test_devrandom_deserialize_smoke() {
        let s = "devRandom:";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::DevRandom(_)))
    }

    /// A smoke test for deserializing devfake rules.
    #[test]
    fn test_devfake_deserialize_smoke() {
        let s = "devFake:";
        let rule: Rule = serde_yaml::from_str(s).expect("Failed to deserialize");
        assert!(matches!(rule, Rule::DevFake(_)))
    }

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
}
