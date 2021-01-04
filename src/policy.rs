// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use crate::libbpfcontain::structs;
use anyhow::{bail, Result};
use serde::Deserialize;

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
    fn default() -> Self {
        Self::WWW
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
    Fs { path: String, access: FileAccess },

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
    File { path: String, access: FileAccess },

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
struct Policy {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_deserialzie() -> Result<()> {
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
