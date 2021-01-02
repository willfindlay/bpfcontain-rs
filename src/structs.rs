// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};
use bitflags::bitflags;
use plain::Plain;

bitflags! {
    /// Represents a policy decision from the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
    #[derive(Default)]
    pub struct PolicyDecision :u8 {
        const NO_DECISION = 0x00;
        const ALLOW       = 0x01;
        const DENY        = 0x02;
    }
}

bitflags! {
    /// Represents the file permissions bitmask on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
    #[derive(Default)]
    pub struct FilePermission :u32 {
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
    }
}

bitflags! {
    /// Represents the capabilities bitmask on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
    #[derive(Default)]
    pub struct Capability :u32 {
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
    /// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
    #[derive(Default)]
    pub struct NetCategory :u8 {
        const WWW = 0x01;
        const IPC = 0x02;
    }
}

bitflags! {
    /// Represents the network operations bitmask on the BPF side.
    ///
    /// # Warning
    ///
    /// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
    #[derive(Default)]
    pub struct NetOperation :u8 {
        const NET_CONNECT  = 0x00000001;
        const NET_BIND     = 0x00000002;
        const NET_ACCEPT   = 0x00000004;
        const NET_LISTEN   = 0x00000008;
        const NET_SEND     = 0x00000010;
        const NET_RECV     = 0x00000020;
        const NET_CREATE   = 0x00000040;
        const NET_SHUTDOWN = 0x00000080;
    }
}

/// Represents a container on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct Container {
    default_deny: u8,
}

unsafe impl Plain for Container {}

/// Represents a process on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct Process {
    container_id: u64,
    pid: u32,
    tgid: u32,
    in_execve: u8,
}

unsafe impl Plain for Process {}

/// Represents a per-filesystem policy key on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct FSPolicyKey {
    container_id: u64,
    device_id: u32,
}

unsafe impl Plain for FSPolicyKey {}

/// Represents a per-file policy key on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct FilePolicyKey {
    container_id: u64,
    inode_id: u64,
    device_id: u32,
}

unsafe impl Plain for FilePolicyKey {}

/// Represents a per-device policy key on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct DevPolicyKey {
    container_id: u64,
    major: u32,
}

unsafe impl Plain for DevPolicyKey {}

/// Represents a capability policy key on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct CapPolicyKey {
    container_id: u64,
}

unsafe impl Plain for CapPolicyKey {}

/// Represents a network policy key on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct NetPolicyKey {
    container_id: u64,
    category: u8,
}

unsafe impl Plain for NetPolicyKey {}

/// Represents a per-inode key on the BPF side.
///
/// # Warning
///
/// Keep this in sync with [bpfcontain.h](src/bpf/bpfcontain.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct InodeKey {
    inode_id: u64,
    device_id: u32,
}

unsafe impl Plain for InodeKey {}
