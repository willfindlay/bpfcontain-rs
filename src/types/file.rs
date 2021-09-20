// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    fmt::Display,
    str::FromStr,
};

use anyhow::bail;
use bit_iter::BitIter;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

use crate::bindings::policy::bitflags::FilePermission as FilePermissionBitflag;

/// Uniquely identifies a file on the fileystem.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FileIdentifier {
    #[serde(alias = "path")]
    Pathname(String),
    #[serde(skip_deserializing)]
    Inode {
        #[serde(rename = "snake_case")]
        inum: u64,
        #[serde(rename = "snake_case")]
        dev: u64,
    },
}

/// Access to a regular file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileAccess {
    #[serde(flatten)]
    file: FileIdentifier,
    access: FilePermissionSet,
}

/// Access patterns that can be applied to filesystem objects
/// such as regular files and devices.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum FilePermission {
    Execute,
    Read,
    Write,
    Append,
    Chmod,
    Delete,
    ExecMmap,
    Link,
    Ioctl,
}

impl Display for FilePermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilePermission::Execute => f.write_str("x"),
            FilePermission::Read => f.write_str("r"),
            FilePermission::Write => f.write_str("w"),
            FilePermission::Append => f.write_str("a"),
            FilePermission::Chmod => f.write_str("c"),
            FilePermission::Delete => f.write_str("d"),
            FilePermission::ExecMmap => f.write_str("m"),
            FilePermission::Link => f.write_str("l"),
            FilePermission::Ioctl => f.write_str("i"),
        }
    }
}

impl FromStr for FilePermission {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 1 {
            bail!("Length of a file access flag must be exactly 1")
        }

        Ok(match &s.to_lowercase()[..] {
            "x" => FilePermission::Execute,
            "r" => FilePermission::Read,
            "w" => FilePermission::Write,
            "a" => FilePermission::Append,
            "c" => FilePermission::Chmod,
            "d" => FilePermission::Delete,
            "m" => FilePermission::ExecMmap,
            "l" => FilePermission::Link,
            "i" => FilePermission::Ioctl,
            s => bail!("Unknown access flag {}", s),
        })
    }
}

impl TryFrom<FilePermissionBitflag> for FilePermission {
    type Error = anyhow::Error;

    fn try_from(value: FilePermissionBitflag) -> Result<Self, Self::Error> {
        Ok(match value {
            FilePermissionBitflag::MAY_EXEC => FilePermission::Execute,
            FilePermissionBitflag::MAY_READ => FilePermission::Read,
            FilePermissionBitflag::MAY_WRITE => FilePermission::Write,
            FilePermissionBitflag::MAY_APPEND => FilePermission::Append,
            FilePermissionBitflag::MAY_CHMOD => FilePermission::Chmod,
            FilePermissionBitflag::MAY_DELETE => FilePermission::Delete,
            FilePermissionBitflag::MAY_EXEC_MMAP => FilePermission::ExecMmap,
            FilePermissionBitflag::MAY_LINK => FilePermission::Link,
            FilePermissionBitflag::MAY_IOCTL => FilePermission::Ioctl,
            v => bail!("Invalid value for `FilePermission` {}", v.bits()),
        })
    }
}

impl From<FilePermission> for FilePermissionBitflag {
    fn from(perm: FilePermission) -> Self {
        match perm {
            FilePermission::Execute => FilePermissionBitflag::MAY_EXEC,
            FilePermission::Read => FilePermissionBitflag::MAY_READ,
            FilePermission::Write => FilePermissionBitflag::MAY_WRITE,
            FilePermission::Append => FilePermissionBitflag::MAY_APPEND,
            FilePermission::Chmod => FilePermissionBitflag::MAY_CHMOD,
            FilePermission::Delete => FilePermissionBitflag::MAY_DELETE,
            FilePermission::ExecMmap => FilePermissionBitflag::MAY_EXEC_MMAP,
            FilePermission::Link => FilePermissionBitflag::MAY_LINK,
            FilePermission::Ioctl => FilePermissionBitflag::MAY_IOCTL,
        }
    }
}

impl<'de> Deserialize<'de> for FilePermission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let perm_str = String::deserialize(deserializer)?;
        FilePermission::from_str(&perm_str).map_err(D::Error::custom)
    }
}

impl Serialize for FilePermission {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.to_string())
    }
}

/// A wrapper around a hashset of [`FilePermission`]s.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FilePermissionSet(HashSet<FilePermission>);

impl Display for FilePermissionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::default();
        for perm in &self.0 {
            s.push_str(&perm.to_string())
        }
        f.write_str(&s)
    }
}

impl FromStr for FilePermissionSet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = HashSet::with_capacity(s.len());

        let mut temp = [0; 4];
        for c in s.to_lowercase().chars() {
            set.insert(FilePermission::from_str(c.encode_utf8(&mut temp))?);
        }

        Ok(FilePermissionSet(set))
    }
}

impl TryFrom<FilePermissionBitflag> for FilePermissionSet {
    type Error = anyhow::Error;

    fn try_from(value: FilePermissionBitflag) -> Result<Self, Self::Error> {
        let mut set = HashSet::default();

        for b in BitIter::from(value.bits()).map(|b| b as u32) {
            let bit = 1 << b;
            let bitflag = FilePermissionBitflag::from_bits(bit).unwrap();
            set.insert(bitflag.try_into()?);
        }

        Ok(FilePermissionSet(set))
    }
}

impl From<FilePermissionSet> for FilePermissionBitflag {
    fn from(perms: FilePermissionSet) -> Self {
        let mut bits = FilePermissionBitflag::default();

        for sig in perms.0 {
            let bit = FilePermissionBitflag::from(sig);
            bits |= bit;
        }

        bits
    }
}

impl<'de> Deserialize<'de> for FilePermissionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let perm_str = String::deserialize(deserializer)?;
        FilePermissionSet::from_str(&perm_str).map_err(D::Error::custom)
    }
}

impl Serialize for FilePermissionSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_permission_from_str_test() {
        // Correct examples
        let p = FilePermission::from_str("r").expect("Failed to convert from string");
        assert!(matches!(p, FilePermission::Read));
        let p = FilePermission::from_str("w").expect("Failed to convert from string");
        assert!(matches!(p, FilePermission::Write));
        let p = FilePermission::from_str("x").expect("Failed to convert from string");
        assert!(matches!(p, FilePermission::Execute));
        // Even capital letters should work
        let p = FilePermission::from_str("X").expect("Failed to convert from string");
        assert!(matches!(p, FilePermission::Execute));

        // Incorrect examples
        FilePermission::from_str("z").expect_err("Should fail to convert from string");
        FilePermission::from_str("rw").expect_err("Should fail to convert from string");
        FilePermission::from_str("rrrrrrrrrr").expect_err("Should fail to convert from string");
    }

    #[test]
    fn file_permission_set_from_str_test() {
        // Correct examples
        let pv = FilePermissionSet::from_str("r").expect("Failed to convert from string");
        assert_eq!(pv.0.len(), 1);
        let pv = FilePermissionSet::from_str("rrrrrrrrr").expect("Failed to convert from string");
        assert_eq!(pv.0.len(), 1);
        let pv = FilePermissionSet::from_str("rwx").expect("Failed to convert from string");
        assert_eq!(pv.0.len(), 3);

        // Incorrect examples
        FilePermissionSet::from_str("z").expect_err("Should fail to convert from string");
        FilePermissionSet::from_str("rwz").expect_err("Should fail to convert from string");
        FilePermissionSet::from_str("rrrrrrrrwwwwwwxxxxxxz")
            .expect_err("Should fail to convert from string");
    }

    #[test]
    fn file_access_deserialize_test() {
        // Example works
        let a: FileAccess = serde_yaml::from_str("{pathname: /foo/bar, access: rwx}")
            .expect("Failed to deserialize");
        assert_eq!(a.file, FileIdentifier::Pathname("/foo/bar".into()));
        assert_eq!(a.access, FilePermissionSet::from_str("rwx").unwrap());

        // Missing fields
        serde_yaml::from_str::<FileAccess>("{access: rwx}")
            .expect_err("Should fail to deserialize");
        serde_yaml::from_str::<FileAccess>("{pathname: /foo/bar}")
            .expect_err("Should fail to deserialize");

        // Invalid access string
        serde_yaml::from_str::<FileAccess>("{pathname: /foo/bar, access: foobar}")
            .expect_err("Should fail to deserialize");
    }
}
