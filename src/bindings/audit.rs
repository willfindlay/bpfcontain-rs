// SPDX-License-Identifier: GPL-2
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

/// A rustified enum representing an audit message type.
///
/// # Warning
///
/// Keep this in sync with [structs.h](src/include/structs.h)
pub type AuditMsg = raw::audit_msg_t;

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
type AuditCommon = raw::audit_common_t;

impl Display for AuditCommon {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let comm = std::str::from_utf8(&self.comm).unwrap_or("Unknown");
        let res =
            PolicyDecision::from_bits(self.decision).expect("Failed to convert policy decision");
        write!(
            f,
            "res={:#?} comm={} pid={} tid={} policy_id={}",
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
            "{} st_ino={} st_dev={} access={:#?}",
            self.common, self.st_ino, self.st_dev, access
        )
    }
}

unsafe impl Pod for AuditFile {}
