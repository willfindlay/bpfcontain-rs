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

/// Place the current process into a container with ID `container_id`.
pub fn containerize(container_id: libc::c_ulong) -> Result<()> {
    let result = unsafe { bindings::containerize(container_id) };

    match result {
        0 => Ok(()),
        n if n == -libc::EAGAIN => bail!("Failed to call into uprobe"),
        n if n == -libc::ENOENT => bail!("No such container with ID {}", container_id),
        n if n == -libc::EINVAL => bail!("Process is already containerized or no room in map"),
        n => bail!("Unknown error {}", n),
    }
}

pub mod structs {
    use super::bindings;
    use bitflags::bitflags;
    use plain::Plain;

    pub use bindings::capability_t;
    pub use bindings::file_permission_t;
    pub use bindings::net_category_t;
    pub use bindings::net_operation_t;
    pub use bindings::policy_decision_t;

    bitflags! {
        /// Represents a policy decision from the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct PolicyDecision :policy_decision_t::Type {
            const NO_DECISION = policy_decision_t::BPFCON_NO_DECISION;
            const ALLOW       = policy_decision_t::BPFCON_ALLOW;
            const DENY        = policy_decision_t::BPFCON_DENY;
            const TAINT       = policy_decision_t::BPFCON_TAINT;
        }
    }

    bitflags! {
        /// Represents the file permissions bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct FileAccess :file_permission_t::Type {
            const MAY_EXEC      = file_permission_t::BPFCON_MAY_EXEC;
            const MAY_WRITE     = file_permission_t::BPFCON_MAY_WRITE;
            const MAY_READ      = file_permission_t::BPFCON_MAY_READ;
            const MAY_APPEND    = file_permission_t::BPFCON_MAY_APPEND;
            const MAY_CREATE    = file_permission_t::BPFCON_MAY_CREATE;
            const MAY_DELETE    = file_permission_t::BPFCON_MAY_DELETE;
            const MAY_RENAME    = file_permission_t::BPFCON_MAY_RENAME;
            const MAY_SETATTR   = file_permission_t::BPFCON_MAY_SETATTR;
            const MAY_CHMOD     = file_permission_t::BPFCON_MAY_CHMOD;
            const MAY_CHOWN     = file_permission_t::BPFCON_MAY_CHOWN;
            const MAY_LINK      = file_permission_t::BPFCON_MAY_LINK;
            const MAY_EXEC_MMAP = file_permission_t::BPFCON_MAY_EXEC_MMAP;
            const MAY_CHDIR     = file_permission_t::BPFCON_MAY_CHDIR;
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
        pub struct Capability :capability_t::Type {
            const NET_BIND_SERVICE = capability_t::BPFCON_CAP_NET_BIND_SERVICE;
            const NET_RAW          = capability_t::BPFCON_CAP_NET_RAW;
            const NET_BROADCAST    = capability_t::BPFCON_CAP_NET_BROADCAST;
            const DAC_OVERRIDE     = capability_t::BPFCON_CAP_DAC_OVERRIDE;
            const DAC_READ_SEARCH  = capability_t::BPFCON_CAP_DAC_READ_SEARCH;
        }
    }

    bitflags! {
        /// Represents the network operations bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct NetOperation :net_operation_t::Type {
            const NET_CONNECT  = net_operation_t::BPFCON_NET_CONNECT;
            const NET_BIND     = net_operation_t::BPFCON_NET_BIND;
            const NET_ACCEPT   = net_operation_t::BPFCON_NET_ACCEPT;
            const NET_LISTEN   = net_operation_t::BPFCON_NET_LISTEN;
            const NET_SEND     = net_operation_t::BPFCON_NET_SEND;
            const NET_RECV     = net_operation_t::BPFCON_NET_RECV;
            const NET_CREATE   = net_operation_t::BPFCON_NET_CREATE;
            const NET_SHUTDOWN = net_operation_t::BPFCON_NET_SHUTDOWN;
            const MASK_SERVER = Self::NET_CREATE.bits | Self::NET_BIND.bits | Self::NET_LISTEN.bits | Self::NET_ACCEPT.bits | Self::NET_SHUTDOWN.bits;
            const MASK_CLIENT = Self::NET_CONNECT.bits;
            const MASK_SEND = Self::NET_SEND.bits;
            const MASK_RECV = Self::NET_RECV.bits;
        }
    }

    /// Represents a container on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::bpfcon_container;
    unsafe impl Plain for bpfcon_container {}

    /// Represents a process on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::bpfcon_process;
    unsafe impl Plain for bpfcon_process {}

    /// Represents a per-filesystem policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::fs_policy_key;
    unsafe impl Plain for fs_policy_key {}

    /// Represents a per-file policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::file_policy_key;
    unsafe impl Plain for file_policy_key {}

    /// Represents a per-device policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::dev_policy_key;
    unsafe impl Plain for dev_policy_key {}

    /// Represents a capability policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::cap_policy_key;
    unsafe impl Plain for cap_policy_key {}

    /// Represents a network policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::net_policy_key;
    unsafe impl Plain for net_policy_key {}

    /// Represents a IPC policy key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::ipc_policy_key;
    unsafe impl Plain for ipc_policy_key {}

    /// Represents a per-inode key on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [structs.h](src/include/structs.h)
    pub use bindings::inode_key;
    unsafe impl Plain for inode_key {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitflag_defaults() {
        assert_eq!(structs::PolicyDecision::default().bits(), 0);
        assert_eq!(structs::FileAccess::default().bits(), 0);
        assert_eq!(structs::Capability::default().bits(), 0);
        assert_eq!(structs::NetOperation::default().bits(), 0);
    }
}
