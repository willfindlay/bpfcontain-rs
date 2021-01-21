// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use crate::bpf::BpfcontainSkel as Skel;
use crate::libbpfcontain::structs;

use anyhow::{Context, Result};
use libbpf_rs::MapFlags;
use pod::Pod;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub trait ToBitflags {
    type BitFlag;
    fn to_bitflags(&self) -> Self::BitFlag;
}

/// Represents a default policy decision.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum DefaultDecision {
    Deny,
    Allow,
    // No Taint
}

impl Default for DefaultDecision {
    /// Policy should default to default-deny if not specified.
    fn default() -> Self {
        DefaultDecision::Deny
    }
}

impl ToBitflags for DefaultDecision {
    type BitFlag = structs::PolicyDecision;

    /// Convert a [`PolicyDecision`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Self::BitFlag {
        match self {
            Self::Deny => Self::BitFlag::DENY,
            Self::Allow => Self::BitFlag::ALLOW,
        }
    }
}

/// Represents a policy decision.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum PolicyDecision {
    Deny,
    Allow,
    Taint,
}

impl ToBitflags for PolicyDecision {
    type BitFlag = structs::PolicyDecision;

    /// Convert a [`PolicyDecision`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Self::BitFlag {
        match self {
            Self::Deny => Self::BitFlag::DENY,
            Self::Allow => Self::BitFlag::ALLOW,
            Self::Taint => Self::BitFlag::TAINT,
        }
    }
}

/// A parseable capability
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Capability {
    /// The CAP_NET_BIND_SERVICE capability.
    /// In YAML this is written as `net-bind-service`.
    NetBindService,
    /// The CAP_NET_RAW capability.
    /// In YAML this is written as `net-raw`.
    NetRaw,
    /// The CAP_NET_BROADCAST capability.
    /// In YAML this is written as `net-broadcast`.
    NetBroadcast,
    /// The CAP_DAC_OVERRIDE capability.
    /// In YAML this is written as `dac-override`.
    DacOverride,
    /// The CAP_DAC_READ_SEARCH capability.
    /// In YAML this is written as `dac-read-search`.
    DacReadSearch,
}

impl ToBitflags for Capability {
    type BitFlag = structs::Capability;

    /// Convert a [`Capability`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Self::BitFlag {
        match self {
            Self::NetBindService => Self::BitFlag::NET_BIND_SERVICE,
            Self::NetRaw => Self::BitFlag::NET_RAW,
            Self::NetBroadcast => Self::BitFlag::NET_BROADCAST,
            Self::DacOverride => Self::BitFlag::DAC_OVERRIDE,
            Self::DacReadSearch => Self::BitFlag::DAC_READ_SEARCH,
        }
    }
}

/// A parseable file access
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum FileAccess {
    /// Read-Only access.
    /// In YAML this is written as `read-only`.
    ReadOnly,
    /// Read-Append access.
    /// In YAML this is written as `read-append`.
    ReadAppend,
    /// Read-Write access.
    /// In YAML this is written as `read-write`.
    ReadWrite,
    /// All access flags together.
    Any,
    /// Generic access flags.
    /// In YAML this is written as `{flags: "rwx"}`, where `rwx` can be any
    /// combination of flags.
    Flags(String),
}

impl ToBitflags for FileAccess {
    type BitFlag = structs::FileAccess;

    /// Convert a [`FileAccess`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Self::BitFlag {
        match self {
            Self::ReadOnly => Self::BitFlag::RO_MASK,
            Self::ReadAppend => Self::BitFlag::RA_MASK,
            Self::ReadWrite => Self::BitFlag::RW_MASK,
            Self::Any => Self::BitFlag::all(),
            Self::Flags(flags) => Self::BitFlag::from_flags(flags),
        }
    }
}

impl Default for FileAccess {
    /// File access should default to read-only unless otherwise specified
    fn default() -> Self {
        FileAccess::ReadOnly
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum NetAccess {
    ClientSend,
    ServerSend,
    ClientRecv,
    ServerRecv,
    Client,
    Server,
    ClientServerSend,
    ClientServerRecv,
    ClientServer,
    Any,
}

impl ToBitflags for NetAccess {
    type BitFlag = structs::NetOperation;

    /// Convert a [`NetAccess`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Self::BitFlag {
        match self {
            Self::ClientSend => Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_SEND,
            Self::ServerSend => Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_SEND,
            Self::ClientRecv => Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_RECV,
            Self::ServerRecv => Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_RECV,
            Self::Client => {
                Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_SEND | Self::BitFlag::MASK_RECV
            }
            Self::Server => {
                Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_SEND | Self::BitFlag::MASK_RECV
            }
            Self::ClientServerSend => {
                Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_SERVER | Self::BitFlag::MASK_SEND
            }
            Self::ClientServerRecv => {
                Self::BitFlag::MASK_CLIENT | Self::BitFlag::MASK_SERVER | Self::BitFlag::MASK_RECV
            }
            Self::ClientServer => {
                Self::BitFlag::MASK_CLIENT
                    | Self::BitFlag::MASK_SERVER
                    | Self::BitFlag::MASK_SEND
                    | Self::BitFlag::MASK_RECV
            }
            Self::Any => Self::BitFlag::all(),
        }
    }
}

impl Default for NetAccess {
    /// NetAccess defaults to ClientServer (with send and receive)
    fn default() -> Self {
        Self::ClientServer
    }
}

/// A parseable rule
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Rule {
    /// A filesystem access rule, specifying a path and an access vector.
    ///
    /// # Examples
    ///
    /// ```yaml
    /// # Short-form
    /// fs: {path: /path/to/fs, access: rwx}
    ///
    /// # Long-form
    /// filesystem:
    ///   path: /path/to/fs
    ///   access: rwx
    /// ```
    #[serde(alias = "fs")]
    Filesystem {
        path: String,
        #[serde(default)]
        access: FileAccess,
    },

    /// A file access rule, specifying a path and an access vector.
    ///
    /// # Examples
    ///
    /// ```yaml
    /// # Short-form
    /// file: {path: /path/to/file, access: rwx}
    ///
    /// # Long-form
    /// file:
    ///   path: /path/to/file
    ///   access: rwx
    /// ```
    File {
        path: String,
        #[serde(default)]
        access: FileAccess,
    },

    /// A capability rule, specifying a single capability.
    ///
    /// # Examples
    ///
    /// ```yaml
    /// # Short-form
    /// cap: dac-override
    ///
    /// # Long-form
    /// capability: net-bind-service
    /// ```
    #[serde(alias = "cap")]
    Capability(Capability),

    /// A network rule, specifying access to the network.
    ///
    /// # Examples
    ///
    /// TODO
    #[serde(alias = "net")]
    Network(NetAccess),

    /// An IPC rule, specifying IPC access to another container.
    ///
    /// # Examples
    ///
    /// TODO
    Ipc(String),

    // High-level policy starts here
    /// Grants read, write, and append access to /dev/pts/* devices
    Terminal,

    /// Grants read access to /dev/[u]random
    Random,

    /// Grants read, write, and append access to /dev/null, /dev/full, /dev/zero
    DevMisc,
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
    pub cmd: String,
    /// Whether the policy is default-allow or default-deny. If this is not
    /// provided, we automatically assume default-deny.
    #[serde(default)]
    default: DefaultDecision,
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
    pub fn policy_id(&self) -> u64 {
        Self::policy_id_for_name(&self.name)
    }

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

    fn policy_id_for_name(name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        hasher.finish()
    }

    pub fn load(&self, skel: &mut Skel) -> Result<()> {
        // Load the `policy_id` into the `policy` eBPF map
        self.load_policy_id(skel)
            .context(format!("Failed to load policy ID "))?;

        // Load rights
        for rule in self.rights.iter() {
            // TODO: Handle errors gracefully
            self.load_rule(skel, rule, PolicyDecision::Allow)
                .context(format!("Failed to load right {:?}", rule))?;
        }

        // Load restrictions
        for rule in self.restrictions.iter() {
            // TODO: Handle errors gracefully
            self.load_rule(skel, rule, PolicyDecision::Deny)
                .context(format!("Failed to load restriction {:?}", rule))?;
        }

        // Load taints
        for rule in self.taints.iter() {
            // TODO: Handle errors gracefully
            self.load_rule(skel, rule, PolicyDecision::Taint)
                .context(format!("Failed to load taint {:?}", rule))?;
        }

        Ok(())
    }

    /// Returns a `(st_dev, st_ino)` pair for the path `path`.
    fn path_to_dev_ino(path: &Path) -> Result<(u64, u64)> {
        use std::fs;
        use std::os::linux::fs::MetadataExt;

        let stat =
            fs::metadata(path).context(format!("Failed to look up metadata for {:?}", path))?;

        Ok((stat.st_dev(), stat.st_ino()))
    }

    /// Returns a vector of (st_dev, st_ino) pairs for the glob `pattern`.
    fn glob_to_dev_ino(pattern: &str) -> Result<Vec<(u64, u64)>> {
        use glob::glob;
        let mut results = vec![];

        for entry in glob(pattern).context(format!("Failed to glob {}", pattern))? {
            if let Ok(path) = entry {
                match Self::path_to_dev_ino(&path) {
                    Ok(res) => results.push(res),
                    Err(e) => log::warn!("Unable to get information for {:?}: {}", path, e),
                }
            }
        }

        Ok(results)
    }

    /// Loads a [`Rule`] into the eBPF map corresponding to the policy decision
    /// [`PolicyDecision`].
    fn load_rule(&self, skel: &mut Skel, rule: &Rule, action: PolicyDecision) -> Result<()> {
        match rule {
            // Handle filesystem rule
            Rule::Filesystem { path, access } => self.load_fs_rule(skel, path, access, &action)?,

            // Handle file rule
            Rule::File { path, access } => self.load_file_rule(skel, path, access, &action)?,

            // Handle capability rule
            Rule::Capability(capability) => self.load_capability_rule(skel, capability, &action)?,

            // Handle network rule
            Rule::Network(access) => self.load_net_rule(skel, access, &action)?,

            // Handle IPC rule
            Rule::Ipc(other) => self.load_ipc_rule(skel, other, &action)?,

            // Handle high level policy
            Rule::Terminal => self.load_terminal_rule(skel, &action)?,
            Rule::Random => self.load_random_rule(skel, &action)?,
            Rule::DevMisc => self.load_devmisc_rule(skel, &action)?,
        };

        Ok(())
    }

    fn load_fs_rule(
        &self,
        skel: &mut Skel,
        path: &str,
        access: &FileAccess,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.fs_allow(),
            PolicyDecision::Deny => maps.fs_deny(),
            PolicyDecision::Taint => maps.fs_taint(),
        };

        let (st_dev, _) = Self::path_to_dev_ino(&PathBuf::from(path))
            .context(format!("Failed to get information for {}", path))?;

        let mut key = structs::FsPolicyKey::zeroed();
        key.policy_id = self.policy_id();
        key.device_id = st_dev as u32;
        let key = key.as_bytes();

        // Update old value with new value
        let mut value: u32 = access.to_bitflags().bits();
        if let Some(old_value) = map
            .lookup(key, MapFlags::ANY)
            .context(format!("Exception during map lookup with key {:?}", key))?
        {
            let old_value: u32 =
                u32::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = value.as_bytes();

        map.update(key, value, MapFlags::ANY).context(format!(
            "Failed to update map key={:?} value={:?}",
            key, value
        ))?;

        Ok(())
    }

    fn load_file_rule(
        &self,
        skel: &mut Skel,
        path: &str,
        access: &FileAccess,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.file_allow(),
            PolicyDecision::Deny => maps.file_deny(),
            PolicyDecision::Taint => maps.file_taint(),
        };

        for (st_dev, st_ino) in
            Self::glob_to_dev_ino(path).context(format!("Failed to glob {}", path))?
        {
            // Set key using st_dev, st_ino, and policy_id
            let mut key = structs::FilePolicyKey::zeroed();
            key.policy_id = self.policy_id();
            key.device_id = st_dev as u32;
            key.inode_id = st_ino;
            let key = key.as_bytes();

            // Update old value with new value
            let mut value: u32 = access.to_bitflags().bits();
            if let Some(old_value) = map
                .lookup(key, MapFlags::ANY)
                .context(format!("Exception during map lookup with key {:?}", key))?
            {
                let old_value: u32 =
                    u32::from_bytes(&old_value).expect("Buffer is too short or not aligned");
                value |= old_value;
            }
            let value = value.as_bytes();

            map.update(key, value, MapFlags::ANY).context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;
        }

        Ok(())
    }

    fn load_capability_rule(
        &self,
        skel: &mut Skel,
        capability: &Capability,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.cap_allow(),
            PolicyDecision::Deny => maps.cap_deny(),
            PolicyDecision::Taint => maps.cap_taint(),
        };

        // Set key using policy_id
        let mut key = structs::CapPolicyKey::zeroed();
        key.policy_id = self.policy_id();
        let key = key.as_bytes();

        // Update old value with new value
        let mut value: u32 = capability.to_bitflags().bits();
        if let Some(old_value) = map
            .lookup(key, MapFlags::ANY)
            .context(format!("Exception during map lookup with key {:?}", key))?
        {
            let old_value: u32 =
                u32::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = value.as_bytes();

        map.update(key, value, MapFlags::ANY).context(format!(
            "Failed to update map key={:?} value={:?}",
            key, value
        ))?;

        Ok(())
    }

    fn load_net_rule(
        &self,
        skel: &mut Skel,
        access: &NetAccess,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.net_allow(),
            PolicyDecision::Deny => maps.net_deny(),
            PolicyDecision::Taint => maps.net_taint(),
        };

        // Set key using policy_id
        let mut key = structs::NetPolicyKey::zeroed();
        key.policy_id = self.policy_id();
        let key = key.as_bytes();

        // Update old value with new value
        let mut value: u32 = access.to_bitflags().bits();
        if let Some(old_value) = map
            .lookup(key, MapFlags::ANY)
            .context(format!("Exception during map lookup with key {:?}", key))?
        {
            let old_value: u32 =
                u32::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = value.as_bytes();

        map.update(key, value, MapFlags::ANY).context(format!(
            "Failed to update map key={:?} value={:?}",
            key, value
        ))?;

        Ok(())
    }

    fn load_ipc_rule(&self, skel: &mut Skel, other: &str, action: &PolicyDecision) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.ipc_allow(),
            PolicyDecision::Deny => maps.ipc_deny(),
            PolicyDecision::Taint => maps.ipc_taint(),
        };

        // Set key using policy_id
        let mut key = structs::IPCPolicyKey::zeroed();
        key.policy_id = self.policy_id();
        key.other_policy_id = Self::policy_id_for_name(other);
        let key = key.as_bytes();

        // Value doesn't matter
        let value: u8 = 1;
        let value = value.as_bytes();

        map.update(key, value, MapFlags::ANY).context(format!(
            "Failed to update map key={:?} value={:?}",
            key, value
        ))?;

        Ok(())
    }

    fn load_terminal_rule(&self, skel: &mut Skel, action: &PolicyDecision) -> Result<()> {
        self.load_device_policy(skel, action, &[(136, structs::MINOR_WILDCARD)], "rwa")
    }

    fn load_random_rule(&self, skel: &mut Skel, action: &PolicyDecision) -> Result<()> {
        self.load_device_policy(skel, action, &[(1, 8), (1, 9)], "r")
    }

    fn load_devmisc_rule(&self, skel: &mut Skel, action: &PolicyDecision) -> Result<()> {
        self.load_device_policy(skel, action, &[(1, 3), (1, 5), (1, 7)], "rwa")
    }

    fn load_device_policy(
        &self,
        skel: &mut Skel,
        action: &PolicyDecision,
        device_nums: &[(u32, u32)],
        access_str: &str,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.dev_allow(),
            PolicyDecision::Deny => maps.dev_deny(),
            PolicyDecision::Taint => maps.dev_taint(),
        };

        // Set value to read file access
        let value: u32 = structs::FileAccess::from_flags(access_str).bits();
        let value = value.as_bytes();

        for &(major, minor) in device_nums {
            // Set key using policy_id
            let mut key = structs::DevPolicyKey::zeroed();
            key.policy_id = self.policy_id();
            key.major = major;
            key.minor = minor;
            let key = key.as_bytes();

            map.update(key, value, MapFlags::ANY).context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;
        }

        Ok(())
    }

    /// Computes and loads the correct `policy_id` into the `policy` eBPF
    /// map.
    fn load_policy_id(&self, skel: &mut Skel) -> Result<()> {
        let key = self.policy_id();
        let mut value = structs::Policy::default();

        // No taint rules implies that we should be tainted by default
        if self.taints.is_empty() {
            value.default_taint = 1;
        } else {
            value.default_taint = 0;
        }

        match self.default {
            DefaultDecision::Allow => value.default_deny = 0,
            DefaultDecision::Deny => value.default_deny = 1,
        };

        let key = key.as_bytes();
        let value = value.as_bytes();

        skel.maps()
            .policies()
            .update(key, value, MapFlags::ANY)
            .context(format!(
                "Failed to update map key={:?} value={:?}",
                key, value
            ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_project_path<P: AsRef<Path>>(path: P) -> PathBuf {
        let project_path = Path::new(file!()).parent().expect("Failed to get parent");
        project_path
            .join("..")
            .join(path)
            .canonicalize()
            .expect("Failed to canonicalize path")
    }

    #[test]
    fn policy_deserialize_test() -> Result<()> {
        let policy_str = "
            name: test_policy
            cmd: /bin/test
            ";

        let policy: Policy = Policy::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, DefaultDecision::Deny);
        assert_eq!(policy.rights, Vec::<Rule>::new());
        assert_eq!(policy.restrictions, Vec::<Rule>::new());

        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: allow
            ";

        let policy: Policy = Policy::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, DefaultDecision::Allow);
        assert_eq!(policy.rights, Vec::<Rule>::new());
        assert_eq!(policy.restrictions, Vec::<Rule>::new());

        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: deny
            ";

        let policy: Policy = Policy::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, DefaultDecision::Deny);
        assert_eq!(policy.rights, Vec::<Rule>::new());
        assert_eq!(policy.restrictions, Vec::<Rule>::new());

        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: allow
            rights:
                - fs: {path: /, access: readWrite}
                - filesystem: {path: /tmp, access: readOnly}
            restrictions:
                - fs:
                    path: /
                    access: {flags: w}
                - file:
                    path: /bin/bash
                    access: {flags: w}
            ";

        let policy: Policy = Policy::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, DefaultDecision::Allow);
        assert_eq!(
            policy.rights,
            vec![
                Rule::Filesystem {
                    path: "/".into(),
                    access: FileAccess::ReadWrite,
                },
                Rule::Filesystem {
                    path: "/tmp".into(),
                    access: FileAccess::ReadOnly,
                }
            ]
        );
        assert_eq!(
            policy.restrictions,
            vec![
                Rule::Filesystem {
                    path: "/".into(),
                    access: FileAccess::Flags("w".into())
                },
                Rule::File {
                    path: "/bin/bash".into(),
                    access: FileAccess::Flags("w".into())
                }
            ]
        );

        // This should fail
        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: taint
            ";
        Policy::from_str(policy_str).expect_err("Shouldn't be able to parse default taint");

        Ok(())
    }

    /// Make sure policy in examples/*.yml parses
    #[test]
    fn parse_examples_smoke_test() -> Result<()> {
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

    #[test]
    fn policy_deserialize_smoke_test() -> Result<()> {
        let policy_str = "
            name: testificate
            cmd: /bin/testificate
            default: allow

            rights:
            - file:
                path: /bin/testificate
                access: {flags: rxm}
            - filesystem:
                path: /tmp
                access: {flags: rwx}
            - fs:
                path: /mnt
                access: readWrite
            - fs:
                path: /dev
            - net: client
            - capability: netBindService

            restrictions:
            - capability: dacOverride
            - capability: dacReadSearch
            ";

        let _policy: Policy = Policy::from_str(policy_str)?;

        Ok(())
    }

    #[test]
    fn policy_id_test() -> Result<()> {
        let mut policy_1 = Policy::default();
        policy_1.name = "discord".into();
        policy_1.cmd = "/bin/discord".into();

        let mut policy_2 = Policy::default();
        policy_2.name = "discord".into();
        policy_2.cmd = "/bin/discord".into();

        assert_eq!(policy_1.policy_id(), policy_2.policy_id());

        Ok(())
    }

    #[test]
    fn fs_rule_deserialize_test() -> Result<()> {
        let rule_str = "
            fs:
                path: /tmp
                access: readOnly
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Filesystem {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: readOnly
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Filesystem {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem: {path: /tmp, access: readOnly}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Filesystem {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: readAppend
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Filesystem {
                access: FileAccess::ReadAppend,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: readWrite
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Filesystem {
                access: FileAccess::ReadWrite,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: {flags: rwx}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Filesystem {
                access: FileAccess::Flags("rwx".into()),
                path: "/tmp".into(),
            }
        );

        Ok(())
    }

    #[test]
    fn file_rule_deserialize_test() -> Result<()> {
        let rule_str = "
            file:
                path: /tmp
                access: readOnly
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            file:
                path: /tmp
                access: readOnly
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            file: {path: /tmp, access: readOnly}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            file:
                path: /tmp
                access: readAppend
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::ReadAppend,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            file:
                path: /tmp
                access: readWrite
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::ReadWrite,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            file:
                path: /tmp
                access: {flags: rwx}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::Flags("rwx".into()),
                path: "/tmp".into(),
            }
        );

        Ok(())
    }

    #[test]
    fn capability_rule_deserialize_test() -> Result<()> {
        let rule_str = "
            cap: netBindService
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetBindService)
        );

        let rule_str = "
            capability: netBindService
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetBindService)
        );

        let rule_str = "
            capability: netRaw
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetRaw)
        );

        let rule_str = "
            capability: netBroadcast
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetBroadcast)
        );

        let rule_str = "
            capability: dacOverride
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::DacOverride)
        );

        let rule_str = "
            capability: dacReadSearch
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::DacReadSearch)
        );

        Ok(())
    }

    #[test]
    fn net_rule_deserialize_test() -> Result<()> {
        let rule_str = "
            network: clientSend
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Network(NetAccess::ClientSend)
        );

        let rule_str = "
            net: server
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Network(NetAccess::Server)
        );

        Ok(())
    }

    #[test]
    fn ipc_rule_deserialize_test() -> Result<()> {
        let rule_str = "
            ipc: other
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Ipc("other".into())
        );

        Ok(())
    }
}
