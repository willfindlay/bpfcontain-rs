// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Structs for audit logging.

use std::fmt::{Display, Formatter};

use pod::Pod;

use super::policy::*;
use super::raw;

/// Represents the common part of an audit event.
///
/// # Warning
///
/// Keep this in sync with [structs.h](src/include/structs.h)
type AuditCommon = raw::audit_common_t;

impl Display for AuditCommon {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let comm = std::str::from_utf8(&self.comm).unwrap_or("Unknown");
        let res =
            PolicyDecision::from_bits(self.decision).expect("Failed to convert policy decision");
        write!(
            f,
            "res={{{:#?}}} comm={{{}}} pid={{{}}} tid={{{}}} policy_id={{{}}}",
            res, comm, self.tgid, self.pid, self.policy_id
        )
    }
}

unsafe impl Pod for AuditCommon {}

/// Represents a file audit event.
///
/// # Warning
///
/// Keep this in sync with [structs.h](src/include/structs.h)
pub type AuditFile = raw::audit_file_t;

impl Display for AuditFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let access = FileAccess::from_bits(self.access).expect("Failed to convert file access");
        write!(
            f,
            "{} st_ino={{{}}} st_dev={{{}}} access={{{:#?}}}",
            self.common, self.st_ino, self.st_dev, access
        )
    }
}

unsafe impl Pod for AuditFile {}

/// Represents a capability audit event.
///
/// # Warning
///
/// Keep this in sync with [structs.h](src/include/structs.h)
pub type AuditCap = raw::audit_cap_t;

impl Display for AuditCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let cap = Capability::from_bits(self.cap).expect("Failed to convert capability");
        write!(f, "{} cap={{{:#?}}}", self.common, cap)
    }
}

unsafe impl Pod for AuditCap {}

/// Represents a network audit event.
///
/// # Warning
///
/// Keep this in sync with [structs.h](src/include/structs.h)
pub type AuditNet = raw::audit_net_t;

impl Display for AuditNet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let operation =
            NetOperation::from_bits(self.operation).expect("Failed to convert network operation");
        write!(f, "{} operation={{{:#?}}}", self.common, operation)
    }
}

unsafe impl Pod for AuditNet {}

/// Represents a capability audit event.
///
/// # Warning
///
/// Keep this in sync with [structs.h](src/include/structs.h)
pub type AuditIpc = raw::audit_ipc_t;

impl Display for AuditIpc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let operation = match self.sender {
            0 => "recv",
            _ => "send",
        };

        write!(
            f,
            "{} operation={{{}}} other_id={{{}}}",
            self.common, operation, self.other_policy_id
        )
    }
}

unsafe impl Pod for AuditIpc {}
