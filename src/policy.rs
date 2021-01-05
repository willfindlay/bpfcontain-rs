// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use crate::bpf::BpfcontainSkel as Skel;
use crate::libbpfcontain::structs;

use anyhow::{bail, Result};
use libbpf_rs::MapFlags;
use serde::Deserialize;
use std::path::PathBuf;

pub trait ToBitflags {
    type BitFlag;
    fn to_bitflags(&self) -> Self::BitFlag;
}

/// Represents a policy decision.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum PolicyDecision {
    /// Default-deny
    Deny,
    /// Default-allow
    Allow,
}

impl ToBitflags for PolicyDecision {
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

impl Default for PolicyDecision {
    /// Policy should default to default-deny if not specified.
    fn default() -> Self {
        PolicyDecision::Deny
    }
}

/// A parseable capability
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
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
    /// Generic access flags.
    /// In YAML this is written as `{flags: "rwx"}`, where `rwx` can be any
    /// combination of flags.
    Flags(String),
}

impl FileAccess {
    /// Convert a file access flag string to a bitmask.
    fn flags_to_access(flags: &String) -> structs::FileAccess {
        let mut access = structs::FileAccess::default();

        // 'x': MAY_EXEC,
        // 'w': MAY_WRITE,
        // 'r': MAY_READ,
        // 'a': MAY_APPEND,
        // 'c': MAY_CREATE,
        // 'd': MAY_DELETE,
        // 'n': MAY_RENAME,
        // 's': MAY_SETATTR,
        // 'p': MAY_CHMOD,
        // 'o': MAY_CHOWN,
        // 'l': MAY_LINK,
        // 'm': MAY_EXEC_MMAP,
        // 't': MAY_CHDIR,

        // Iterate through the characters in our access flags, creating the
        // bitmask as we go.
        for c in flags.chars() {
            // Because of weird Rust-isms, to_lowercase returns a string. We
            // only care about ASCII chars, so we will match on length-1
            // strings.
            let c_lo = &c.to_lowercase().to_string()[..];
            match c_lo {
                "x" => access |= structs::FileAccess::MAY_EXEC,
                "w" => access |= structs::FileAccess::MAY_WRITE,
                "r" => access |= structs::FileAccess::MAY_READ,
                "a" => access |= structs::FileAccess::MAY_APPEND,
                "c" => access |= structs::FileAccess::MAY_CREATE,
                "d" => access |= structs::FileAccess::MAY_DELETE,
                "n" => access |= structs::FileAccess::MAY_RENAME,
                "s" => access |= structs::FileAccess::MAY_SETATTR,
                "p" => access |= structs::FileAccess::MAY_CHMOD,
                "o" => access |= structs::FileAccess::MAY_CHOWN,
                "l" => access |= structs::FileAccess::MAY_LINK,
                "m" => access |= structs::FileAccess::MAY_EXEC_MMAP,
                "t" => access |= structs::FileAccess::MAY_CHDIR,
                _ => log::warn!("Unknown access flag {}", c),
            };
        }

        access
    }
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
            Self::Flags(flags) => Self::flags_to_access(flags),
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
#[serde(rename_all = "lowercase")]
enum NetCategory {
    WWW,
    IPC,
    All,
}

impl ToBitflags for NetCategory {
    type BitFlag = structs::NetCategory;

    /// Convert a [`NetCategory`] into a bitflag representation for loading into an
    /// eBPF map.
    fn to_bitflags(&self) -> Self::BitFlag {
        match self {
            Self::WWW => Self::BitFlag::WWW,
            Self::IPC => Self::BitFlag::IPC,
            Self::All => Self::BitFlag::all(),
        }
    }
}

impl Default for NetCategory {
    /// NetCategory defaults to both WWW and IPC
    fn default() -> Self {
        Self::All
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
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
    #[serde(rename = "filesystem")]
    #[serde(alias = "fs")]
    Fs {
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
    #[serde(rename = "file")]
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
    #[serde(rename = "capability")]
    #[serde(alias = "cap")]
    Capability(Capability),

    /// A network rule, specifying access to the network.
    ///
    /// # Examples
    ///
    /// TODO
    #[serde(rename = "network")]
    #[serde(alias = "net")]
    Network {
        #[serde(default)]
        category: NetCategory,
        #[serde(default)]
        access: NetAccess,
    },
}

/// A high-level representation of a BPFContain policy that has been loaded
/// from a YAML file.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy's name. Should be unique.
    /// A policy _must_ specify a name.
    name: String,
    /// The command associated with the policy. This will be run when the user
    /// invokes `bpfcontain-rs run </path/to/policy.yml>`.
    /// A policy _must_ specify a command.
    cmd: String,
    /// Whether the policy is default-allow or default-deny. If this is not
    /// provided, we automatically assume default-deny.
    #[serde(default)]
    default: PolicyDecision,
    /// The rights (allow-rules) associated with the policy.
    #[serde(default)]
    rights: Vec<Rule>,
    /// The restrictions (deny-rules) associated with the policy.
    #[serde(default)]
    restrictions: Vec<Rule>,
}

impl Policy {
    pub fn compute_container_id(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.name.hash(&mut hasher);

        hasher.finish()
    }

    pub fn load(&self, skel: &mut Skel) -> Result<()> {
        // Load the `container_id` into the `containers` eBPF map
        self.load_container(skel)?;

        // Load rights
        for rule in self.rights.iter() {
            self.load_rule(skel, rule, PolicyDecision::Allow)?;
        }

        // Load restrictions
        for rule in self.restrictions.iter() {
            self.load_rule(skel, rule, PolicyDecision::Deny)?;
        }

        Ok(())
    }

    /// Returns a `(st_dev, st_ino)` pair for the path `path`.
    fn path_to_dev_ino(path: &PathBuf) -> Result<(u64, u64)> {
        use std::fs;
        use std::os::linux::fs::MetadataExt;

        let stat = fs::metadata(path)?;

        Ok((stat.st_dev(), stat.st_ino()))
    }

    /// Returns a vector of (st_dev, st_ino) pairs for the glob `pattern`.
    fn glob_to_dev_ino(pattern: &String) -> Result<Vec<(u64, u64)>> {
        use glob::glob;
        let mut results = vec![];

        for entry in glob(pattern)? {
            if let Ok(path) = entry {
                match Self::path_to_dev_ino(&path) {
                    Ok(res) => results.push(res),
                    Err(e) => log::error!("{}", e),
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
            Rule::Fs { path, access } => self.load_fs_rule(skel, path, access, &action)?,

            // Handle file rule
            Rule::File { path, access } => self.load_file_rule(skel, path, access, &action)?,

            // Handle capability rule
            Rule::Capability(capability) => self.load_capability_rule(skel, capability, &action)?,

            // Handle network rule
            Rule::Network { category, access } => {
                self.load_net_rule(skel, category, access, &action)?
            }
        };

        Ok(())
    }

    fn load_fs_rule(
        &self,
        skel: &mut Skel,
        path: &String,
        access: &FileAccess,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.fs_allow(),
            PolicyDecision::Deny => maps.fs_deny(),
        };

        let (st_dev, _) = Self::path_to_dev_ino(&PathBuf::from(path))?;

        // Set key using st_dev and container_id
        let mut key = structs::fs_policy_key::default();
        key.container_id = self.compute_container_id();
        key.device_id = st_dev as u32;
        let key = unsafe { plain::as_bytes(&key) };

        // Update old value with new value
        let mut value: u32 = access.to_bitflags().bits();
        if let Some(old_value) = map.lookup(key, MapFlags::ANY)? {
            let old_value: u32 =
                *plain::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = unsafe { plain::as_bytes(&value) };

        map.update(key, value, MapFlags::ANY)?;

        Ok(())
    }

    fn load_file_rule(
        &self,
        skel: &mut Skel,
        path: &String,
        access: &FileAccess,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.file_allow(),
            PolicyDecision::Deny => maps.file_deny(),
        };

        let (st_dev, st_ino) = Self::path_to_dev_ino(&PathBuf::from(path))?;

        // Set key using st_dev, st_ino, and container_id
        let mut key = structs::file_policy_key::default();
        key.container_id = self.compute_container_id();
        key.device_id = st_dev as u32;
        key.inode_id = st_ino;
        let key = unsafe { plain::as_bytes(&key) };

        // Update old value with new value
        let mut value: u32 = access.to_bitflags().bits();
        if let Some(old_value) = map.lookup(key, MapFlags::ANY)? {
            let old_value: u32 =
                *plain::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = unsafe { plain::as_bytes(&value) };

        map.update(key, value, MapFlags::ANY)?;

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
        };

        // Set key using container_id
        let mut key = structs::cap_policy_key::default();
        key.container_id = self.compute_container_id();
        let key = unsafe { plain::as_bytes(&key) };

        // Update old value with new value
        let mut value: u32 = capability.to_bitflags().bits();
        if let Some(old_value) = map.lookup(key, MapFlags::ANY)? {
            let old_value: u32 =
                *plain::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = unsafe { plain::as_bytes(&value) };

        map.update(key, value, MapFlags::ANY)?;

        Ok(())
    }

    fn load_net_rule(
        &self,
        skel: &mut Skel,
        category: &NetCategory,
        access: &NetAccess,
        action: &PolicyDecision,
    ) -> Result<()> {
        // Look up the correct map
        let mut maps = skel.maps();
        let map = match action {
            PolicyDecision::Allow => maps.net_allow(),
            PolicyDecision::Deny => maps.net_deny(),
        };

        // Set key using container_id
        let mut key = structs::net_policy_key::default();
        key.container_id = self.compute_container_id();
        // This should be fine, as net category's bitmask will always be below 255
        key.category = category.to_bitflags().bits() as u8;
        let key = unsafe { plain::as_bytes(&key) };

        // Update old value with new value
        let mut value: u32 = access.to_bitflags().bits();
        if let Some(old_value) = map.lookup(key, MapFlags::ANY)? {
            let old_value: u32 =
                *plain::from_bytes(&old_value).expect("Buffer is too short or not aligned");
            value |= old_value;
        }
        let value = unsafe { plain::as_bytes(&value) };

        map.update(key, value, MapFlags::ANY)?;

        Ok(())
    }

    /// Computes and loads the correct `container_id` into the `containers` eBPF
    /// map.
    fn load_container(&self, skel: &mut Skel) -> Result<()> {
        let key = self.compute_container_id();
        let mut value = structs::bpfcon_container::default();

        match self.default {
            PolicyDecision::Allow => value.default_deny = 0,
            PolicyDecision::Deny => value.default_deny = 1,
        };

        let key = unsafe { plain::as_bytes(&key) };
        let value = unsafe { plain::as_bytes(&value) };

        skel.maps().containers().update(key, value, MapFlags::ANY)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_deserialize() -> Result<()> {
        let policy_str = "
            name: test_policy
            cmd: /bin/test
            ";

        let policy: Policy = serde_yaml::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, PolicyDecision::Deny);
        assert_eq!(policy.rights, Vec::<Rule>::new());
        assert_eq!(policy.restrictions, Vec::<Rule>::new());

        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: allow
            ";

        let policy: Policy = serde_yaml::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, PolicyDecision::Allow);
        assert_eq!(policy.rights, Vec::<Rule>::new());
        assert_eq!(policy.restrictions, Vec::<Rule>::new());

        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: deny
            ";

        let policy: Policy = serde_yaml::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, PolicyDecision::Deny);
        assert_eq!(policy.rights, Vec::<Rule>::new());
        assert_eq!(policy.restrictions, Vec::<Rule>::new());

        let policy_str = "
            name: test_policy
            cmd: /bin/test
            default: allow
            rights:
                - fs: {path: /, access: read-write}
                - filesystem: {path: /tmp, access: read-only}
            restrictions:
                - fs:
                    path: /
                    access: {flags: w}
                - file:
                    path: /bin/bash
                    access: {flags: w}
            ";

        let policy: Policy = serde_yaml::from_str(policy_str)?;
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.cmd, "/bin/test");
        assert_eq!(policy.default, PolicyDecision::Allow);
        assert_eq!(
            policy.rights,
            vec![
                Rule::Fs {
                    path: "/".into(),
                    access: FileAccess::ReadWrite,
                },
                Rule::Fs {
                    path: "/tmp".into(),
                    access: FileAccess::ReadOnly,
                }
            ]
        );
        assert_eq!(
            policy.restrictions,
            vec![
                Rule::Fs {
                    path: "/".into(),
                    access: FileAccess::Flags("w".into())
                },
                Rule::File {
                    path: "/bin/bash".into(),
                    access: FileAccess::Flags("w".into())
                }
            ]
        );

        Ok(())
    }

    #[test]
    fn test_policy_deserialize_smoke() -> Result<()> {
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
                access: read-write
            - fs:
                path: /dev
            - net:
                category: www
                access: client
            - capability: net-bind-service

            restrictions:
            - capability: dac-override
            - capability: dac-read-search
            ";

        let _policy: Policy = serde_yaml::from_str(policy_str)?;

        Ok(())
    }

    #[test]
    fn test_policy_id() -> Result<()> {
        let mut policy_1 = Policy::default();
        policy_1.name = "discord".into();
        policy_1.cmd = "/bin/discord".into();

        let mut policy_2 = Policy::default();
        policy_2.name = "discord".into();
        policy_2.cmd = "/bin/discord".into();

        assert_eq!(
            policy_1.compute_container_id(),
            policy_2.compute_container_id()
        );

        Ok(())
    }

    #[test]
    fn test_fs_rule_deserialize() -> Result<()> {
        let rule_str = "
            fs:
                path: /tmp
                access: read-only
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Fs {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: read-only
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Fs {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem: {path: /tmp, access: read-only}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Fs {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: read-append
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Fs {
                access: FileAccess::ReadAppend,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            filesystem:
                path: /tmp
                access: read-write
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Fs {
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
            Rule::Fs {
                access: FileAccess::Flags("rwx".into()),
                path: "/tmp".into(),
            }
        );

        Ok(())
    }

    #[test]
    fn test_file_rule_deserialize() -> Result<()> {
        let rule_str = "
            file:
                path: /tmp
                access: read-only
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
                access: read-only
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::File {
                access: FileAccess::ReadOnly,
                path: "/tmp".into(),
            }
        );

        let rule_str = "
            file: {path: /tmp, access: read-only}
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
                access: read-append
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
                access: read-write
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
    fn test_capability_rule_deserialize() -> Result<()> {
        let rule_str = "
            cap: net-bind-service
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetBindService)
        );

        let rule_str = "
            capability: net-bind-service
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetBindService)
        );

        let rule_str = "
            capability: net-raw
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetRaw)
        );

        let rule_str = "
            capability: net-broadcast
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::NetBroadcast)
        );

        let rule_str = "
            capability: dac-override
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::DacOverride)
        );

        let rule_str = "
            capability: dac-read-search
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Capability(Capability::DacReadSearch)
        );

        Ok(())
    }

    #[test]
    fn test_net_rule_deserialize() -> Result<()> {
        let rule_str = "
            network: {}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Network {
                category: NetCategory::default(),
                access: NetAccess::default()
            }
        );

        let rule_str = "
            network:
                category: www
                access: client-send
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Network {
                category: NetCategory::WWW,
                access: NetAccess::ClientSend
            }
        );

        let rule_str = "
            net: {category: ipc, access: server}
            ";

        assert_eq!(
            serde_yaml::from_str::<Rule>(rule_str)?,
            Rule::Network {
                category: NetCategory::IPC,
                access: NetAccess::Server
            }
        );

        Ok(())
    }
}
