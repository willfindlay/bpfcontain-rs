// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::MapFlags;
use pod::Pod;
use serde::Deserialize;

use crate::bindings;
use crate::bpf::BpfcontainSkel as Skel;
use crate::policy::rules::*;
use crate::utils::{glob_to_dev_ino, path_to_dev_ino, ToBitflags};

/// Represents a default enforcement type
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum DefaultEnforcement {
    Deny,
    Allow,
}

impl Default for DefaultEnforcement {
    /// Policy should default to default-deny if not specified.
    fn default() -> Self {
        DefaultEnforcement::Deny
    }
}

impl ToBitflags for DefaultEnforcement {
    type BitFlag = bindings::policy::PolicyDecision;

    /// Convert a [`PolicyDecision`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Result<Self::BitFlag> {
        Ok(match self {
            Self::Deny => Self::BitFlag::DENY,
            Self::Allow => Self::BitFlag::ALLOW,
        })
    }
}

/// A high-level representation of a BPFContain policy that has been loaded
/// from a YAML file.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy's name. Should be unique.
    /// A policy _must_ specify a name.
    pub name: String,
    /// The command associated with the policy. This will be run when the user
    /// invokes `bpfcontain-rs run </path/to/policy.yml>`.
    /// A policy _must_ specify a command.
    #[serde(alias = "entry")]
    pub cmd: String,
    /// Whether the policy is default-allow or default-deny. If this is not
    /// provided, we automatically assume default-deny.
    #[serde(default)]
    default: DefaultEnforcement,
    /// The rights (allow-rules) associated with the policy.
    #[serde(default)]
    rights: Vec<Rule>,
    /// The restrictions (deny-rules) associated with the policy.
    #[serde(default)]
    restrictions: Vec<Rule>,
    /// The taints (taint-rules) associated with the policy.
    #[serde(default)]
    taints: Vec<Rule>,
}

impl Policy {
    /// Construct a new policy by parsing the YAML policy file located at `path`.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        use std::fs::File;

        let reader = File::open(&path).context("Failed to open policy file for reading")?;

        serde_yaml::from_reader(reader).context("Failed to parse policy file")
    }

    /// Construct a new policy by parsing a YAML `string`.
    pub fn from_str(string: &str) -> Result<Self> {
        serde_yaml::from_str(string).context("Failed to parse policy string")
    }

    pub fn policy_id(&self) -> u64 {
        Self::policy_id_for_name(&self.name)
    }

    fn policy_id_for_name(name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        hasher.finish()
    }

    pub fn default_taint(&self) -> bool {
        self.taints.len() == 0
    }

    pub fn default_deny(&self) -> bool {
        self.default == DefaultEnforcement::Deny
    }

    pub fn load(&self, skel: &mut Skel) -> Result<()> {
        // Load rights
        for rule in self.rights.iter() {
            // TODO: Handle errors gracefully
            rule.load(self, skel, PolicyDecision::Allow)
                .context("Failed to load rule")?;
        }

        // Load restrictions
        for rule in self.restrictions.iter() {
            // TODO: Handle errors gracefully
            rule.load(self, skel, PolicyDecision::Deny)
                .context("Failed to load rule")?;
        }

        // Load taints
        for rule in self.taints.iter() {
            // TODO: Handle errors gracefully
            rule.load(self, skel, PolicyDecision::Taint)
                .context("Failed to load rule")?;
        }

        Ok(())
    }
}

///// A parseable capability
//#[derive(Deserialize, Debug, Clone, PartialEq)]
//#[serde(rename_all = "camelCase")]
//enum Capability {
//    /// The CAP_NET_BIND_SERVICE capability.
//    /// In YAML this is written as `net-bind-service`.
//    NetBindService,
//    /// The CAP_NET_RAW capability.
//    /// In YAML this is written as `net-raw`.
//    NetRaw,
//    /// The CAP_NET_BROADCAST capability.
//    /// In YAML this is written as `net-broadcast`.
//    NetBroadcast,
//    /// The CAP_DAC_OVERRIDE capability.
//    /// In YAML this is written as `dac-override`.
//    DacOverride,
//    /// The CAP_DAC_READ_SEARCH capability.
//    /// In YAML this is written as `dac-read-search`.
//    DacReadSearch,
//}
//
//impl ToBitflags for Capability {
//    type BitFlag = policy::Capability;
//
//    /// Convert a [`Capability`] into a bitflag representation for loading into an
//    /// eBPF map.
//    fn to_bitflags(&self) -> Self::BitFlag {
//        match self {
//            Self::NetBindService => Self::BitFlag::NET_BIND_SERVICE,
//            Self::NetRaw => Self::BitFlag::NET_RAW,
//            Self::NetBroadcast => Self::BitFlag::NET_BROADCAST,
//            Self::DacOverride => Self::BitFlag::DAC_OVERRIDE,
//            Self::DacReadSearch => Self::BitFlag::DAC_READ_SEARCH,
//        }
//    }
//}
//
///// A parseable file access
//#[derive(Deserialize, Debug, Clone, PartialEq)]
//#[serde(rename_all = "camelCase")]
//enum FileAccess {
//    /// Read-Only access.
//    /// In YAML this is written as `read-only`.
//    ReadOnly,
//    /// Read-Append access.
//    /// In YAML this is written as `read-append`.
//    ReadAppend,
//    /// Read-Write access.
//    /// In YAML this is written as `read-write`.
//    ReadWrite,
//    /// All access flags together.
//    Any,
//    /// Generic access flags.
//    /// In YAML this is written as `{flags: "rwx"}`, where `rwx` can be any
//    /// combination of flags.
//    Flags(String),
//}
//
//impl ToBitflags for FileAccess {
//    type BitFlag = policy::FileAccess;
//
//    /// Convert a [`FileAccess`] into a bitflag representation for loading into an
//    /// eBPF map.
//    fn to_bitflags(&self) -> Self::BitFlag {
//        match self {
//            Self::ReadOnly => Self::BitFlag::RO_MASK,
//            Self::ReadAppend => Self::BitFlag::RA_MASK,
//            Self::ReadWrite => Self::BitFlag::RW_MASK,
//            Self::Any => Self::BitFlag::all(),
//            Self::Flags(flags) => Self::BitFlag::from_flags(flags),
//        }
//    }
//}
//
//impl Default for FileAccess {
//    /// File access should default to read-only unless otherwise specified
//    fn default() -> Self {
//        FileAccess::ReadOnly
//    }
//}
//
//#[derive(Deserialize, Debug, Clone, PartialEq)]
//#[serde(rename_all = "camelCase")]
//enum NetAccess {
//    Client,
//    Server,
//    Send,
//    Recv,
//    Any,
//}
//
//impl ToBitflags for NetAccess {
//    type BitFlag = policy::NetOperation;
//
//    /// Convert a [`NetAccess`] into a bitflag representation for loading into an
//    /// eBPF map.
//    fn to_bitflags(&self) -> Self::BitFlag {
//        match self {
//            Self::Client => Self::BitFlag::MASK_CLIENT,
//            Self::Server => Self::BitFlag::MASK_SERVER,
//            Self::Send => Self::BitFlag::MASK_SEND,
//            Self::Recv => Self::BitFlag::MASK_RECV,
//            Self::Any => Self::BitFlag::all(),
//        }
//    }
//}
//
//impl Default for NetAccess {
//    /// NetAccess defaults to Any
//    fn default() -> Self {
//        Self::Any
//    }
//}
//
///// A parseable rule
//#[derive(Deserialize, Debug, Clone, PartialEq)]
//#[serde(rename_all = "camelCase")]
//enum Rule {
//    /// A filesystem access rule, specifying a path and an access vector.
//    ///
//    /// # Examples
//    ///
//    /// ```yaml
//    /// # Short-form
//    /// fs: {path: /path/to/fs, access: rwx}
//    ///
//    /// # Long-form
//    /// filesystem:
//    ///   path: /path/to/fs
//    ///   access: rwx
//    /// ```
//    #[serde(alias = "fs")]
//    Filesystem {
//        path: String,
//        #[serde(default)]
//        access: FileAccess,
//    },
//
//    /// A file access rule, specifying a path and an access vector.
//    ///
//    /// # Examples
//    ///
//    /// ```yaml
//    /// # Short-form
//    /// file: {path: /path/to/file, access: rwx}
//    ///
//    /// # Long-form
//    /// file:
//    ///   path: /path/to/file
//    ///   access: rwx
//    /// ```
//    File {
//        path: String,
//        #[serde(default)]
//        access: FileAccess,
//    },
//
//    /// A capability rule, specifying a single capability.
//    ///
//    /// # Examples
//    ///
//    /// ```yaml
//    /// # Short-form
//    /// cap: dac-override
//    ///
//    /// # Long-form
//    /// capability: net-bind-service
//    /// ```
//    #[serde(alias = "cap")]
//    Capability(Capability),
//
//    /// A network rule, specifying access to the network.
//    ///
//    /// # Examples
//    ///
//    /// TODO
//    #[serde(alias = "net")]
//    Network(Vec<NetAccess>),
//
//    /// An IPC rule, specifying IPC access to another container.
//    ///
//    /// # Examples
//    ///
//    /// TODO
//    Ipc(String),
//
//    // High-level policy starts here
//    /// Grants read, write, and append access to /dev/pts/* devices
//    #[serde(alias = "tty")]
//    Terminal,
//
//    /// Grants read access to /dev/[u]random
//    Random,
//
//    /// Grants read, write, and append access to /dev/null, /dev/full, /dev/zero
//    DevMisc,
//}

///// Loads a [`Rule`] into the eBPF map corresponding to the policy decision
///// [`PolicyDecision`].
//fn load_rule(&self, skel: &mut Skel, rule: &Rule, action: PolicyDecision) -> Result<()> {
//    match rule {
//        // Handle filesystem rule
//        Rule::Filesystem { path, access } => self.load_fs_rule(skel, path, access, &action)?,
//
//        // Handle file rule
//        Rule::File { path, access } => self.load_file_rule(skel, path, access, &action)?,
//
//        // Handle capability rule
//        Rule::Capability(capability) => self.load_capability_rule(skel, capability, &action)?,
//
//        // Handle network rule
//        Rule::Network(accesses) => self.load_net_rule(skel, accesses, &action)?,
//
//        // Handle IPC rule
//        Rule::Ipc(other) => self.load_ipc_rule(skel, other, &action)?,
//
//        // Handle high level policy
//        Rule::Terminal => self.load_terminal_rule(skel, &action)?,
//        Rule::Random => self.load_random_rule(skel, &action)?,
//        Rule::DevMisc => self.load_devmisc_rule(skel, &action)?,
//    };
//
//    Ok(())
//}
//
//fn load_fs_rule(
//    &self,
//    skel: &mut Skel,
//    path: &str,
//    access: &FileAccess,
//    action: &PolicyDecision,
//) -> Result<()> {
//    // Look up the correct map
//    let mut maps = skel.maps();
//    let map = maps.fs_policy();
//
//    let (st_dev, _) = path_to_dev_ino(&PathBuf::from(path))
//        .context(format!("Failed to get information for {}", path))?;
//
//    let mut key = policy::FsPolicyKey::zeroed();
//    key.policy_id = self.policy_id();
//    key.device_id = st_dev as u32;
//    let key = key.as_bytes();
//
//    // Update old value with new value
//    let mut value = policy::FilePolicyVal::default();
//    match action {
//        PolicyDecision::Allow => value.allow = access.to_bitflags().bits(),
//        PolicyDecision::Taint => value.taint = access.to_bitflags().bits(),
//        PolicyDecision::Deny => value.deny = access.to_bitflags().bits(),
//    }
//    if let Some(old_value) = map
//        .lookup(key, MapFlags::ANY)
//        .context(format!("Exception during map lookup with key {:?}", key))?
//    {
//        let old_value = policy::FilePolicyVal::from_bytes(&old_value)
//            .expect("Buffer is too short or not aligned");
//        value.allow |= old_value.allow;
//        value.taint |= old_value.taint;
//        value.deny |= old_value.deny;
//    }
//    let value = value.as_bytes();
//
//    map.update(key, value, MapFlags::ANY).context(format!(
//        "Failed to update map key={:?} value={:?}",
//        key, value
//    ))?;
//
//    Ok(())
//}
//
//fn load_file_rule(
//    &self,
//    skel: &mut Skel,
//    path: &str,
//    access: &FileAccess,
//    action: &PolicyDecision,
//) -> Result<()> {
//    // Look up the correct map
//    let mut maps = skel.maps();
//    let map = maps.file_policy();
//
//    for (st_dev, st_ino) in
//        Self::glob_to_dev_ino(path).context(format!("Failed to glob {}", path))?
//    {
//        // Set key using st_dev, st_ino, and policy_id
//        let mut key = policy::FilePolicyKey::zeroed();
//        key.policy_id = self.policy_id();
//        key.device_id = st_dev as u32;
//        key.inode_id = st_ino;
//        let key = key.as_bytes();
//
//        // Update old value with new value
//        let mut value = policy::FilePolicyVal::default();
//        match action {
//            PolicyDecision::Allow => value.allow = access.to_bitflags().bits(),
//            PolicyDecision::Taint => value.taint = access.to_bitflags().bits(),
//            PolicyDecision::Deny => value.deny = access.to_bitflags().bits(),
//        }
//        if let Some(old_value) = map
//            .lookup(key, MapFlags::ANY)
//            .context(format!("Exception during map lookup with key {:?}", key))?
//        {
//            let old_value = policy::FilePolicyVal::from_bytes(&old_value)
//                .expect("Buffer is too short or not aligned");
//            value.allow |= old_value.allow;
//            value.taint |= old_value.taint;
//            value.deny |= old_value.deny;
//        }
//        let value = value.as_bytes();
//
//        map.update(key, value, MapFlags::ANY).context(format!(
//            "Failed to update map key={:?} value={:?}",
//            key, value
//        ))?;
//    }
//
//    Ok(())
//}
//
//fn load_capability_rule(
//    &self,
//    skel: &mut Skel,
//    capability: &Capability,
//    action: &PolicyDecision,
//) -> Result<()> {
//    // Look up the correct map
//    let mut maps = skel.maps();
//    let map = maps.cap_policy();
//
//    // Set key using policy_id
//    let mut key = policy::CapPolicyKey::zeroed();
//    key.policy_id = self.policy_id();
//    let key = key.as_bytes();
//
//    // Update old value with new value
//    let mut value = policy::CapPolicyVal::default();
//    match action {
//        PolicyDecision::Allow => value.allow = capability.to_bitflags().bits(),
//        PolicyDecision::Taint => value.taint = capability.to_bitflags().bits(),
//        PolicyDecision::Deny => value.deny = capability.to_bitflags().bits(),
//    }
//    if let Some(old_value) = map
//        .lookup(key, MapFlags::ANY)
//        .context(format!("Exception during map lookup with key {:?}", key))?
//    {
//        let old_value = policy::CapPolicyVal::from_bytes(&old_value)
//            .expect("Buffer is too short or not aligned");
//        value.allow |= old_value.allow;
//        value.taint |= old_value.taint;
//        value.deny |= old_value.deny;
//    }
//    let value = value.as_bytes();
//
//    map.update(key, value, MapFlags::ANY).context(format!(
//        "Failed to update map key={:?} value={:?}",
//        key, value
//    ))?;
//
//    Ok(())
//}
//
//fn load_net_rule(
//    &self,
//    skel: &mut Skel,
//    accesses: &Vec<NetAccess>,
//    action: &PolicyDecision,
//) -> Result<()> {
//    // Look up the correct map
//    let mut maps = skel.maps();
//    let map = maps.net_policy();
//
//    // Set key using policy_id
//    let mut key = policy::NetPolicyKey::zeroed();
//    key.policy_id = self.policy_id();
//    let key = key.as_bytes();
//
//    let mut access = policy::NetOperation::empty();
//    for a in accesses {
//        access |= a.to_bitflags();
//    }
//
//    // Update old value with new value
//    let mut value = policy::NetPolicyVal::default();
//    match action {
//        PolicyDecision::Allow => value.allow = access.bits(),
//        PolicyDecision::Taint => value.taint = access.bits(),
//        PolicyDecision::Deny => value.deny = access.bits(),
//    }
//    if let Some(old_value) = map
//        .lookup(key, MapFlags::ANY)
//        .context(format!("Exception during map lookup with key {:?}", key))?
//    {
//        let old_value = policy::NetPolicyVal::from_bytes(&old_value)
//            .expect("Buffer is too short or not aligned");
//        value.allow |= old_value.allow;
//        value.taint |= old_value.taint;
//        value.deny |= old_value.deny;
//    }
//    let value = value.as_bytes();
//
//    map.update(key, value, MapFlags::ANY).context(format!(
//        "Failed to update map key={:?} value={:?}",
//        key, value
//    ))?;
//
//    Ok(())
//}
//
//fn load_ipc_rule(&self, skel: &mut Skel, other: &str, action: &PolicyDecision) -> Result<()> {
//    // Look up the correct map
//    let mut maps = skel.maps();
//    let map = maps.ipc_policy();
//
//    // Set key using policy_id
//    let mut key = policy::IPCPolicyKey::zeroed();
//    key.policy_id = self.policy_id();
//    key.other_policy_id = Self::policy_id_for_name(other);
//    let key = key.as_bytes();
//
//    // Value doesn't matter
//    let mut value = policy::IpcPolicyVal::default();
//    value.decision = action.to_bitflags().bits();
//    if let Some(old_value) = map
//        .lookup(key, MapFlags::ANY)
//        .context(format!("Exception during map lookup with key {:?}", key))?
//    {
//        let old_value = policy::IpcPolicyVal::from_bytes(&old_value)
//            .expect("Buffer is too short or not aligned");
//        value.decision |= old_value.decision;
//    }
//    let value = value.as_bytes();
//
//    map.update(key, value, MapFlags::ANY).context(format!(
//        "Failed to update map key={:?} value={:?}",
//        key, value
//    ))?;
//
//    Ok(())
//}
//
//fn load_terminal_rule(&self, skel: &mut Skel, action: &PolicyDecision) -> Result<()> {
//    self.load_device_policy(
//        skel,
//        action,
//        &[(136, policy::DevPolicyKey::wildcard())],
//        "rwa",
//    )
//}
//
//fn load_random_rule(&self, skel: &mut Skel, action: &PolicyDecision) -> Result<()> {
//    self.load_device_policy(skel, action, &[(1, 8), (1, 9)], "r")
//}
//
//fn load_devmisc_rule(&self, skel: &mut Skel, action: &PolicyDecision) -> Result<()> {
//    self.load_device_policy(skel, action, &[(1, 3), (1, 5), (1, 7)], "rwa")
//}
//
//fn load_device_policy(
//    &self,
//    skel: &mut Skel,
//    action: &PolicyDecision,
//    device_nums: &[(u32, i64)],
//    access_str: &str,
//) -> Result<()> {
//    // Look up the correct map
//    let mut maps = skel.maps();
//    let map = maps.dev_policy();
//
//    // Set value to read file access
//    let mut value = policy::FilePolicyVal::default();
//    match action {
//        PolicyDecision::Allow => {
//            value.allow = policy::FileAccess::from_flags(access_str).bits()
//        }
//        PolicyDecision::Taint => {
//            value.taint = policy::FileAccess::from_flags(access_str).bits()
//        }
//        PolicyDecision::Deny => value.deny = policy::FileAccess::from_flags(access_str).bits(),
//    }
//    let value = value.as_bytes();
//
//    for &(major, minor) in device_nums {
//        // Set key using policy_id
//        let mut key = policy::DevPolicyKey::zeroed();
//        key.policy_id = self.policy_id();
//        key.major = major;
//        key.minor = minor;
//        let key = key.as_bytes();
//
//        map.update(key, value, MapFlags::ANY).context(format!(
//            "Failed to update map key={:?} value={:?}",
//            key, value
//        ))?;
//    }
//
//    Ok(())
//}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_project_path;

    /// Make sure policy in examples/*.yml parses
    #[test]
    fn parse_examples_smoke() -> Result<()> {
        let examples_path = get_project_path("examples");
        let mut examples_str = examples_path
            .to_str()
            .expect("Failed to convert examples_path to string")
            .to_string();
        examples_str.push_str("/**/*.yml");

        for path in glob::glob(&examples_str)
            .expect("Failed to glob")
            .filter_map(Result::ok)
        {
            Policy::from_path(&path)
                .context(format!("Failed to parse policy from path {:?}", path))?;
        }

        Ok(())
    }
}
