// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};

/// Include bindings from [`bindings.rs`](lib/bindings.rs)
mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!("libbpfcontain/bindings.rs");
}

/// Place the current process into a container with ID `policy_id`.
pub fn containerize(policy_id: libc::c_ulong) -> Result<()> {
    let result = unsafe { bindings::containerize(policy_id) };

    match result {
        0 => Ok(()),
        n if n == -libc::EAGAIN => bail!("Failed to call into uprobe"),
        n if n == -libc::ENOENT => bail!("No such container with ID {}", policy_id),
        n if n == -libc::EINVAL => bail!("Process is already containerized or no room in map"),
        n => bail!("Unknown error {}", n),
    }
}

pub mod structs {
    use super::bindings;
    use bitflags::bitflags;
    use pod::Pod;
    use std::fmt::{Display, Formatter};

    pub const MINOR_WILDCARD: u32 = u32::MAX;

    bitflags! {
        /// Represents a policy decision from the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct PolicyDecision :bindings::policy_decision_t::Type {
            const NO_DECISION = bindings::policy_decision_t::BPFCON_NO_DECISION;
            const ALLOW       = bindings::policy_decision_t::BPFCON_ALLOW;
            const DENY        = bindings::policy_decision_t::BPFCON_DENY;
            const TAINT       = bindings::policy_decision_t::BPFCON_TAINT;
        }
    }

    bitflags! {
        /// Represents the file permissions bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct FileAccess :bindings::file_permission_t::Type {
            const MAY_EXEC      = bindings::file_permission_t::BPFCON_MAY_EXEC;
            const MAY_WRITE     = bindings::file_permission_t::BPFCON_MAY_WRITE;
            const MAY_READ      = bindings::file_permission_t::BPFCON_MAY_READ;
            const MAY_APPEND    = bindings::file_permission_t::BPFCON_MAY_APPEND;
            const MAY_CREATE    = bindings::file_permission_t::BPFCON_MAY_CREATE;
            const MAY_DELETE    = bindings::file_permission_t::BPFCON_MAY_DELETE;
            const MAY_RENAME    = bindings::file_permission_t::BPFCON_MAY_RENAME;
            const MAY_SETATTR   = bindings::file_permission_t::BPFCON_MAY_SETATTR;
            const MAY_CHMOD     = bindings::file_permission_t::BPFCON_MAY_CHMOD;
            const MAY_CHOWN     = bindings::file_permission_t::BPFCON_MAY_CHOWN;
            const MAY_LINK      = bindings::file_permission_t::BPFCON_MAY_LINK;
            const MAY_EXEC_MMAP = bindings::file_permission_t::BPFCON_MAY_EXEC_MMAP;
            const MAY_CHDIR     = bindings::file_permission_t::BPFCON_MAY_CHDIR;
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
        pub struct Capability :bindings::capability_t::Type {
            const NET_BIND_SERVICE = bindings::capability_t::BPFCON_CAP_NET_BIND_SERVICE;
            const NET_RAW          = bindings::capability_t::BPFCON_CAP_NET_RAW;
            const NET_BROADCAST    = bindings::capability_t::BPFCON_CAP_NET_BROADCAST;
            const DAC_OVERRIDE     = bindings::capability_t::BPFCON_CAP_DAC_OVERRIDE;
            const DAC_READ_SEARCH  = bindings::capability_t::BPFCON_CAP_DAC_READ_SEARCH;
        }
    }

    bitflags! {
        /// Represents the network operations bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct NetOperation :bindings::net_operation_t::Type {
            const NET_CONNECT  = bindings::net_operation_t::BPFCON_NET_CONNECT;
            const NET_BIND     = bindings::net_operation_t::BPFCON_NET_BIND;
            const NET_ACCEPT   = bindings::net_operation_t::BPFCON_NET_ACCEPT;
            const NET_LISTEN   = bindings::net_operation_t::BPFCON_NET_LISTEN;
            const NET_SEND     = bindings::net_operation_t::BPFCON_NET_SEND;
            const NET_RECV     = bindings::net_operation_t::BPFCON_NET_RECV;
            const NET_CREATE   = bindings::net_operation_t::BPFCON_NET_CREATE;
            const NET_SHUTDOWN = bindings::net_operation_t::BPFCON_NET_SHUTDOWN;
            const MASK_SERVER = Self::NET_CREATE.bits | Self::NET_BIND.bits | Self::NET_LISTEN.bits | Self::NET_ACCEPT.bits | Self::NET_SHUTDOWN.bits;
            const MASK_CLIENT = Self::NET_CONNECT.bits;
            const MASK_SEND = Self::NET_SEND.bits;
            const MASK_RECV = Self::NET_RECV.bits;
        }
    }

    // TODO delete
    /// A rustified enum representing event action.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type EventAction = bindings::event_action_t;

    impl Display for EventAction {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::EA_UNKNOWN => write!(f, "none"),
                Self::EA_ERROR => write!(f, "error"),
                Self::EA_DENY => write!(f, "policy deny"),
                Self::EA_IMPLICIT_DENY => write!(f, "implicit deny"),
                Self::EA_TAINT => write!(f, "policy taint"),
            }
        }
    }

    /// A rustified enum representing an audit message type.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type AuditMsg = bindings::audit_msg_t;

    impl Display for AuditMsg {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::AUDIT_UNKNOWN => write!(f, "unknown event"),
                Self::AUDIT_ERROR => write!(f, "error"),
                Self::AUDIT_DENY => write!(f, "policy deny"),
                Self::AUDIT_IMPLICIT_DENY => write!(f, "implicit deny"),
                Self::AUDIT_TAINT => write!(f, "policy taint"),
            }
        }
    }

    /// Represents the common part of an audit event.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    type AuditCommon = bindings::audit_common_t;

    impl Display for AuditCommon {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let comm = std::str::from_utf8(&self.comm).unwrap_or("Unknown");
            write!(
                f,
                "decision={} comm={} pid={} tid={} policy_id={}",
                self.decision, comm, self.tgid, self.pid, self.policy_id
            )
        }
    }

    /// Represents a file audit event.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type AuditFile = bindings::audit_file_t;

    impl Display for AuditFile {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let pathname = std::str::from_utf8(&self.pathname).unwrap_or("Unknown");
            write!(
                f,
                "{} path={} access={}",
                self.common, pathname, self.access
            )
        }
    }

    /// A rustified enum representing event type.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type EventType = bindings::event_type_t;

    /// Represents an event for logging on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type Event = bindings::event_t;
    unsafe impl Pod for Event {}

    impl Display for Event {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let comm = std::str::from_utf8(&self.comm).unwrap_or("Unknown");
            let general_info = format!(
                "action={} comm={} pid={} tid={} policy_id={} type={:?}",
                self.action, comm, self.pid, self.tgid, self.policy_id, self.info.type_
            );
            let specific_info = unsafe {
                match self.info.type_ {
                    EventType::ET_NONE => "".to_string(),
                    EventType::ET_FILE => format!(
                        "inode={}, device_id={} operation={:?}",
                        self.info.info.file_info.inode_id,
                        self.info.info.file_info.device_id,
                        FileAccess::from_bits(self.info.info.file_info.access)
                    ),
                    EventType::ET_CAP => format!(
                        "capability={:?}",
                        Capability::from_bits(self.info.info.cap_info.cap)
                    ),
                    EventType::ET_NET => format!(
                        "operation={:?}",
                        NetOperation::from_bits(self.info.info.net_info.operation)
                    ),
                    EventType::ET_IPC => format!(
                        "sender_pid={} sender_policy_id={} \
                        receiver_pid={} receiver_policy_id={}",
                        self.info.info.ipc_info.sender_pid,
                        self.info.info.ipc_info.sender_id,
                        self.info.info.ipc_info.receiver_pid,
                        self.info.info.ipc_info.receiver_id
                    ),
                    EventType::ET_NO_SUCH_CONTAINER => {
                        format!("msg=\"No such container with ID {}\"", self.policy_id)
                    }
                }
            };

            write!(f, "{} {}", general_info, specific_info)
        }
    }

    /// Represents a container on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type Policy = bindings::policy_t;
    unsafe impl Pod for Policy {}

    /// Represents a process on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type Process = bindings::process_t;
    unsafe impl Pod for Process {}

    /// Represents a per-filesystem policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type FsPolicyKey = bindings::fs_policy_key_t;
    unsafe impl Pod for FsPolicyKey {}

    /// Represents a per-file policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type FilePolicyKey = bindings::file_policy_key_t;
    unsafe impl Pod for FilePolicyKey {}

    /// Represents a per-device policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type DevPolicyKey = bindings::dev_policy_key_t;
    unsafe impl Pod for DevPolicyKey {}

    /// Represents a capability policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type CapPolicyKey = bindings::cap_policy_key_t;
    unsafe impl Pod for CapPolicyKey {}

    /// Represents a network policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type NetPolicyKey = bindings::net_policy_key_t;
    unsafe impl Pod for NetPolicyKey {}

    /// Represents a IPC policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type IPCPolicyKey = bindings::ipc_policy_key_t;
    unsafe impl Pod for IPCPolicyKey {}

    /// Represents a per-inode key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub type InodeKey = bindings::inode_key_t;
    unsafe impl Pod for InodeKey {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitflag_defaults_test() {
        assert_eq!(structs::PolicyDecision::default().bits(), 0);
        assert_eq!(structs::FileAccess::default().bits(), 0);
        assert_eq!(structs::Capability::default().bits(), 0);
        assert_eq!(structs::NetOperation::default().bits(), 0);
    }
}
