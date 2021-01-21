// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use anyhow::{bail, Result};

/// Include bindings from [`bindings.rs`](lib/bindings.rs)
mod bindings {
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
        pub struct PolicyDecision :bindings::PolicyDecision::Type {
            const NO_DECISION = bindings::PolicyDecision::BPFCON_NO_DECISION;
            const ALLOW       = bindings::PolicyDecision::BPFCON_ALLOW;
            const DENY        = bindings::PolicyDecision::BPFCON_DENY;
            const TAINT       = bindings::PolicyDecision::BPFCON_TAINT;
        }
    }

    bitflags! {
        /// Represents the file permissions bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct FileAccess :bindings::FilePermission::Type {
            const MAY_EXEC      = bindings::FilePermission::BPFCON_MAY_EXEC;
            const MAY_WRITE     = bindings::FilePermission::BPFCON_MAY_WRITE;
            const MAY_READ      = bindings::FilePermission::BPFCON_MAY_READ;
            const MAY_APPEND    = bindings::FilePermission::BPFCON_MAY_APPEND;
            const MAY_CREATE    = bindings::FilePermission::BPFCON_MAY_CREATE;
            const MAY_DELETE    = bindings::FilePermission::BPFCON_MAY_DELETE;
            const MAY_RENAME    = bindings::FilePermission::BPFCON_MAY_RENAME;
            const MAY_SETATTR   = bindings::FilePermission::BPFCON_MAY_SETATTR;
            const MAY_CHMOD     = bindings::FilePermission::BPFCON_MAY_CHMOD;
            const MAY_CHOWN     = bindings::FilePermission::BPFCON_MAY_CHOWN;
            const MAY_LINK      = bindings::FilePermission::BPFCON_MAY_LINK;
            const MAY_EXEC_MMAP = bindings::FilePermission::BPFCON_MAY_EXEC_MMAP;
            const MAY_CHDIR     = bindings::FilePermission::BPFCON_MAY_CHDIR;
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
        pub struct Capability :bindings::Capability::Type {
            const NET_BIND_SERVICE = bindings::Capability::BPFCON_CAP_NET_BIND_SERVICE;
            const NET_RAW          = bindings::Capability::BPFCON_CAP_NET_RAW;
            const NET_BROADCAST    = bindings::Capability::BPFCON_CAP_NET_BROADCAST;
            const DAC_OVERRIDE     = bindings::Capability::BPFCON_CAP_DAC_OVERRIDE;
            const DAC_READ_SEARCH  = bindings::Capability::BPFCON_CAP_DAC_READ_SEARCH;
        }
    }

    bitflags! {
        /// Represents the network operations bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct NetOperation :bindings::NetOperation::Type {
            const NET_CONNECT  = bindings::NetOperation::BPFCON_NET_CONNECT;
            const NET_BIND     = bindings::NetOperation::BPFCON_NET_BIND;
            const NET_ACCEPT   = bindings::NetOperation::BPFCON_NET_ACCEPT;
            const NET_LISTEN   = bindings::NetOperation::BPFCON_NET_LISTEN;
            const NET_SEND     = bindings::NetOperation::BPFCON_NET_SEND;
            const NET_RECV     = bindings::NetOperation::BPFCON_NET_RECV;
            const NET_CREATE   = bindings::NetOperation::BPFCON_NET_CREATE;
            const NET_SHUTDOWN = bindings::NetOperation::BPFCON_NET_SHUTDOWN;
            const MASK_SERVER = Self::NET_CREATE.bits | Self::NET_BIND.bits | Self::NET_LISTEN.bits | Self::NET_ACCEPT.bits | Self::NET_SHUTDOWN.bits;
            const MASK_CLIENT = Self::NET_CONNECT.bits;
            const MASK_SEND = Self::NET_SEND.bits;
            const MASK_RECV = Self::NET_RECV.bits;
        }
    }

    /// A rustified enum representing event action.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::EventAction;

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

    /// A rustified enum representing event type.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::EventType;

    /// Represents an event for logging on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::Event;
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
    pub use bindings::Policy;
    unsafe impl Pod for Policy {}

    /// Represents a process on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::Process;
    unsafe impl Pod for Process {}

    /// Represents a per-filesystem policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::FsPolicyKey;
    unsafe impl Pod for FsPolicyKey {}

    /// Represents a per-file policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::FilePolicyKey;
    unsafe impl Pod for FilePolicyKey {}

    /// Represents a per-device policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::DevPolicyKey;
    unsafe impl Pod for DevPolicyKey {}

    /// Represents a capability policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::CapPolicyKey;
    unsafe impl Pod for CapPolicyKey {}

    /// Represents a network policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::NetPolicyKey;
    unsafe impl Pod for NetPolicyKey {}

    /// Represents a IPC policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::IPCPolicyKey;
    unsafe impl Pod for IPCPolicyKey {}

    /// Represents a per-inode key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::InodeKey;
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
