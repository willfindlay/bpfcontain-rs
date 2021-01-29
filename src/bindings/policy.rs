// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Structs representing bpfcontain policy.

use bitflags::bitflags;
use pod::Pod;

use super::raw;

/// Represents a policy on the BPF side.
pub type Policy = raw::policy_t;
unsafe impl Pod for Policy {}

/// Represents a per-filesystem policy key on the BPF side.
pub type FsPolicyKey = raw::fs_policy_key_t;
unsafe impl Pod for FsPolicyKey {}

/// Represents a per-file policy key on the BPF side.
pub type FilePolicyKey = raw::file_policy_key_t;
unsafe impl Pod for FilePolicyKey {}

/// Represents a per-device policy key on the BPF side.
pub type DevPolicyKey = raw::dev_policy_key_t;
unsafe impl Pod for DevPolicyKey {}

impl DevPolicyKey {
    pub fn wildcard() -> i64 {
        raw::MINOR_WILDCARD
    }
}

/// Represents a capability policy key on the BPF side.
pub type CapPolicyKey = raw::cap_policy_key_t;
unsafe impl Pod for CapPolicyKey {}

/// Represents a network policy key on the BPF side.
pub type NetPolicyKey = raw::net_policy_key_t;
unsafe impl Pod for NetPolicyKey {}

/// Represents a IPC policy key on the BPF side.
pub type IPCPolicyKey = raw::ipc_policy_key_t;
unsafe impl Pod for IPCPolicyKey {}

// bitflags below this line ----------------------------------------------------
// warning: these must be kept in sync with the BPF side

bitflags! {
    /// Represents a policy decision from the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    #[derive(Default)]
    pub struct PolicyDecision :raw::policy_decision_t::Type {
        const NO_DECISION = raw::policy_decision_t::BPFCON_NO_DECISION;
        const ALLOW       = raw::policy_decision_t::BPFCON_ALLOW;
        const DENY        = raw::policy_decision_t::BPFCON_DENY;
        const TAINT       = raw::policy_decision_t::BPFCON_TAINT;
    }
}

bitflags! {
    /// Represents the file permissions bitmask on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    #[derive(Default)]
    pub struct FileAccess :raw::file_permission_t::Type {
        const MAY_EXEC      = raw::file_permission_t::BPFCON_MAY_EXEC;
        const MAY_WRITE     = raw::file_permission_t::BPFCON_MAY_WRITE;
        const MAY_READ      = raw::file_permission_t::BPFCON_MAY_READ;
        const MAY_APPEND    = raw::file_permission_t::BPFCON_MAY_APPEND;
        const MAY_CREATE    = raw::file_permission_t::BPFCON_MAY_CREATE;
        const MAY_DELETE    = raw::file_permission_t::BPFCON_MAY_DELETE;
        const MAY_RENAME    = raw::file_permission_t::BPFCON_MAY_RENAME;
        const MAY_SETATTR   = raw::file_permission_t::BPFCON_MAY_SETATTR;
        const MAY_CHMOD     = raw::file_permission_t::BPFCON_MAY_CHMOD;
        const MAY_CHOWN     = raw::file_permission_t::BPFCON_MAY_CHOWN;
        const MAY_LINK      = raw::file_permission_t::BPFCON_MAY_LINK;
        const MAY_EXEC_MMAP = raw::file_permission_t::BPFCON_MAY_EXEC_MMAP;
        const MAY_CHDIR     = raw::file_permission_t::BPFCON_MAY_CHDIR;
        const RO_MASK = Self::MAY_READ.bits | Self::MAY_CHDIR.bits;
        const RA_MASK = Self::RO_MASK.bits | Self::MAY_APPEND.bits | Self::MAY_CREATE.bits;
        const RW_MASK = Self::RA_MASK.bits | Self::MAY_WRITE.bits;
    }
}

impl FileAccess {
    /// Create a file access mask from string flags.
    ///
    /// This function will ignore invalid flags, logging a warning when it
    /// does to.
    ///
    /// Mappings are as follows:
    /// ```yaml
    /// 'x' -> MAY_EXEC
    /// 'w' -> MAY_WRITE
    /// 'r' -> MAY_READ
    /// 'a' -> MAY_APPEND
    /// 'c' -> MAY_CREATE
    /// 'd' -> MAY_DELETE
    /// 'n' -> MAY_RENAME
    /// 's' -> MAY_SETATTR
    /// 'p' -> MAY_CHMOD
    /// 'o' -> MAY_CHOWN
    /// 'l' -> MAY_LINK
    /// 'm' -> MAY_EXEC_MMAP
    /// 't' -> MAY_CHDIR
    /// ```
    pub fn from_flags(flags: &str) -> Self {
        let mut access = Self::default();
        // Iterate through the characters in our access flags, creating the
        // bitmask as we go.
        for c in flags.chars() {
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
                _ => log::warn!("Unknown access flag {}", c),
            };
        }

        access
    }
}

bitflags! {
    /// Represents the capabilities bitmask on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    #[derive(Default)]
    pub struct Capability :raw::capability_t::Type {
        const CHOWN = raw::capability_t::BPFCON_CAP_CHOWN;
        const DAC_OVERRIDE = raw::capability_t::BPFCON_CAP_DAC_OVERRIDE;
        const DAC_READ_SEARCH = raw::capability_t::BPFCON_CAP_DAC_READ_SEARCH;
        const FOWNER = raw::capability_t::BPFCON_CAP_FOWNER;
        const FSETID = raw::capability_t::BPFCON_CAP_FSETID;
        const KILL = raw::capability_t::BPFCON_CAP_KILL;
        const SETGID = raw::capability_t::BPFCON_CAP_SETGID;
        const SETUID = raw::capability_t::BPFCON_CAP_SETUID;
        const SETPCAP = raw::capability_t::BPFCON_CAP_SETPCAP;
        const LINUX_IMMUTABLE = raw::capability_t::BPFCON_CAP_LINUX_IMMUTABLE;
        const NET_BIND_SERVICE = raw::capability_t::BPFCON_CAP_NET_BIND_SERVICE;
        const NET_BROADCAST = raw::capability_t::BPFCON_CAP_NET_BROADCAST;
        const NET_ADMIN = raw::capability_t::BPFCON_CAP_NET_ADMIN;
        const NET_RAW = raw::capability_t::BPFCON_CAP_NET_RAW;
        const IPC_LOCK = raw::capability_t::BPFCON_CAP_IPC_LOCK;
        const IPC_OWNER = raw::capability_t::BPFCON_CAP_IPC_OWNER;
        const SYS_MODULE = raw::capability_t::BPFCON_CAP_SYS_MODULE;
        const SYS_RAWIO = raw::capability_t::BPFCON_CAP_SYS_RAWIO;
        const SYS_CHROOT = raw::capability_t::BPFCON_CAP_SYS_CHROOT;
        const SYS_PTRACE = raw::capability_t::BPFCON_CAP_SYS_PTRACE;
        const SYS_PACCT = raw::capability_t::BPFCON_CAP_SYS_PACCT;
        const SYS_ADMIN = raw::capability_t::BPFCON_CAP_SYS_ADMIN;
        const SYS_BOOT = raw::capability_t::BPFCON_CAP_SYS_BOOT;
        const SYS_NICE = raw::capability_t::BPFCON_CAP_SYS_NICE;
        const SYS_RESOURCE = raw::capability_t::BPFCON_CAP_SYS_RESOURCE;
        const SYS_TIME = raw::capability_t::BPFCON_CAP_SYS_TIME;
        const SYS_TTY_CONFIG = raw::capability_t::BPFCON_CAP_SYS_TTY_CONFIG;
        const MKNOD = raw::capability_t::BPFCON_CAP_MKNOD;
        const LEASE = raw::capability_t::BPFCON_CAP_LEASE;
        const AUDIT_WRITE = raw::capability_t::BPFCON_CAP_AUDIT_WRITE;
        const AUDIT_CONTROL = raw::capability_t::BPFCON_CAP_AUDIT_CONTROL;
        const SETFCAP = raw::capability_t::BPFCON_CAP_SETFCAP;
        const MAC_OVERRIDE = raw::capability_t::BPFCON_CAP_MAC_OVERRIDE;
        const MAC_ADMIN = raw::capability_t::BPFCON_CAP_MAC_ADMIN;
        const SYSLOG = raw::capability_t::BPFCON_CAP_SYSLOG;
        const WAKE_ALARM = raw::capability_t::BPFCON_CAP_WAKE_ALARM;
        const BLOCK_SUSPEND = raw::capability_t::BPFCON_CAP_BLOCK_SUSPEND;
        const AUDIT_READ = raw::capability_t::BPFCON_CAP_AUDIT_READ;
        const PERFMON = raw::capability_t::BPFCON_CAP_PERFMON;
        const BPF = raw::capability_t::BPFCON_CAP_BPF;
        const CHECKPOINT_RESTORE = raw::capability_t::BPFCON_CAP_CHECKPOINT_RESTORE;
    }
}

bitflags! {
    /// Represents the network operations bitmask on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    #[derive(Default)]
    pub struct NetOperation :raw::net_operation_t::Type {
        const NET_CONNECT  = raw::net_operation_t::BPFCON_NET_CONNECT;
        const NET_BIND     = raw::net_operation_t::BPFCON_NET_BIND;
        const NET_ACCEPT   = raw::net_operation_t::BPFCON_NET_ACCEPT;
        const NET_LISTEN   = raw::net_operation_t::BPFCON_NET_LISTEN;
        const NET_SEND     = raw::net_operation_t::BPFCON_NET_SEND;
        const NET_RECV     = raw::net_operation_t::BPFCON_NET_RECV;
        const NET_CREATE   = raw::net_operation_t::BPFCON_NET_CREATE;
        const NET_SHUTDOWN = raw::net_operation_t::BPFCON_NET_SHUTDOWN;
        const MASK_SERVER = Self::NET_CREATE.bits | Self::NET_BIND.bits
            | Self::NET_LISTEN.bits | Self::NET_ACCEPT.bits | Self::NET_SHUTDOWN.bits;
        const MASK_CLIENT = Self::NET_CONNECT.bits;
        const MASK_SEND = Self::NET_SEND.bits;
        const MASK_RECV = Self::NET_RECV.bits;
    }
}
