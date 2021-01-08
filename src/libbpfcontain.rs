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
        pub struct PolicyDecision :policy_decision_t {
            const NO_DECISION = 0x00;
            const ALLOW       = 0x01;
            const DENY        = 0x02;
            const TAINT       = 0x04;
        }
    }

    bitflags! {
        /// Represents the file permissions bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct FileAccess :file_permission_t {
            const MAY_EXEC      = 0x00000001;
            const MAY_WRITE     = 0x00000002;
            const MAY_READ      = 0x00000004;
            const MAY_APPEND    = 0x00000008;
            const MAY_CREATE    = 0x00000010;
            const MAY_DELETE    = 0x00000020;
            const MAY_RENAME    = 0x00000040;
            const MAY_SETATTR   = 0x00000080;
            const MAY_CHMOD     = 0x00000100;
            const MAY_CHOWN     = 0x00000200;
            const MAY_LINK      = 0x00000400;
            const MAY_EXEC_MMAP = 0x00000800;
            const MAY_CHDIR     = 0x00001000;
            const RO_MASK = Self::MAY_READ.bits | Self::MAY_CHDIR.bits;
            const RA_MASK = Self::RO_MASK.bits | Self::MAY_APPEND.bits | Self::MAY_CREATE.bits;
            const RW_MASK = Self::RA_MASK.bits | Self::MAY_WRITE.bits;
        }
    }

    bitflags! {
        /// Represents the capabilities bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct Capability :capability_t {
            const NET_BIND_SERVICE = 0x00000001;
            const NET_RAW          = 0x00000002;
            const NET_BROADCAST    = 0x00000004;
            const DAC_OVERRIDE     = 0x00000008;
            const DAC_READ_SEARCH  = 0x00000010;
        }
    }

    bitflags! {
        /// Represents the network categories bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct NetCategory :net_category_t {
            const WWW = 0x01;
            const IPC = 0x02;
        }
    }

    bitflags! {
        /// Represents the network operations bitmask on the BPF side.
        ///
        /// # Warning
        ///
        /// Keep this in sync with [structs.h](src/include/structs.h)
        #[derive(Default)]
        pub struct NetOperation :net_operation_t {
            const NET_CONNECT  = 0x00000001;
            const NET_BIND     = 0x00000002;
            const NET_ACCEPT   = 0x00000004;
            const NET_LISTEN   = 0x00000008;
            const NET_SEND     = 0x00000010;
            const NET_RECV     = 0x00000020;
            const NET_CREATE   = 0x00000040;
            const NET_SHUTDOWN = 0x00000080;
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
        assert_eq!(structs::NetCategory::default().bits(), 0);
        assert_eq!(structs::NetOperation::default().bits(), 0);
    }
}
