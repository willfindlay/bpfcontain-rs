// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Structs for audit logging.

use std::fmt::{Display, Formatter};

use plain::Plain;

use super::policy::bitflags::{Capability, FilePermission, NetOperation, Signal};
use super::raw;

/// Represents the common part of an audit event.
pub type AuditData = raw::audit_data_t;

impl Display for AuditData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let comm = std::str::from_utf8(&self.comm).unwrap_or("Unknown");

        // Convert inner type into string representation
        // SAFETY: We assert that the BPF program will always transmit the correct type flag
        // corresponding with the inner union.
        let inner_data_str = unsafe {
            match self.type_ {
                AuditType::AUDIT_TYPE_FILE => self.__bindgen_anon_1.file.to_string(),
                AuditType::AUDIT_TYPE_CAP => self.__bindgen_anon_1.cap.to_string(),
                AuditType::AUDIT_TYPE_NET => self.__bindgen_anon_1.net.to_string(),
                AuditType::AUDIT_TYPE_IPC => self.__bindgen_anon_1.ipc.to_string(),
                AuditType::AUDIT_TYPE_SIGNAL => self.__bindgen_anon_1.signal.to_string(),
                AuditType::AUDIT_TYPE__UNKOWN => "UNKNOWN".to_string(),
            }
        };

        write!(
            f,
            "[{}] comm={} pid={} ns_pid={} policy={} {}",
            self.level, comm, self.pid, self.ns_pid, self.policy_id, inner_data_str
        )
    }
}

unsafe impl Plain for AuditData {}

/// Represents a file audit event.
pub type AuditFile = raw::audit_file_t;

impl Display for AuditFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let access = FilePermission::from_bits(self.access).expect("Failed to convert file access");
        write!(
            f,
            "kind=file st_ino={} st_dev={} access={:?}",
            self.st_ino, self.st_dev, access
        )
    }
}

unsafe impl Plain for AuditFile {}

/// Represents a capability audit event.
pub type AuditCap = raw::audit_cap_t;

impl Display for AuditCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let cap = Capability::from_bits(self.cap).expect("Failed to convert capability");
        write!(f, "kind=capability cap={:?}", cap)
    }
}

unsafe impl Plain for AuditCap {}

/// Represents a network audit event.
pub type AuditNet = raw::audit_net_t;

impl Display for AuditNet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let operation =
            NetOperation::from_bits(self.operation).expect("Failed to convert network operation");
        write!(f, "kind=network operation={:?}", operation)
    }
}

unsafe impl Plain for AuditNet {}

/// Represents a capability audit event.
pub type AuditIpc = raw::audit_ipc_t;

impl Display for AuditIpc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let operation = match self.sender {
            0 => "recv",
            _ => "send",
        };
        write!(
            f,
            "kind=ipc operation={} other_id={}",
            operation, self.other_policy_id
        )
    }
}

unsafe impl Plain for AuditIpc {}

pub type AuditSignal = raw::audit_signal_t;

impl Display for AuditSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let access = Signal::from_bits(self.signal).expect("Failed to convert signal number");
        write!(
            f,
            "kind=signal signal={:?} receiver_policy_id={}",
            access, self.other_policy_id
        )
    }
}

unsafe impl Plain for AuditSignal {}

pub type AuditType = raw::audit_type_t;

pub type AuditLevel = raw::audit_level_t;

impl Display for AuditLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let level = match self {
            level if level == &Self::AUDIT_ALLOW => "ALLOW",
            level if level == &Self::AUDIT_DENY => "DENY",
            level if level == &Self::AUDIT_TAINT => "TAINT",
            // FIXME: Others are unsupported for now
            _ => return Err(std::fmt::Error),
        };
        write!(f, "{}", level)
    }
}
