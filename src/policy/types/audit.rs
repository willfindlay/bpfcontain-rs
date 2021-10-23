// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use std::convert::TryFrom;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::{
    bindings::{
        audit::{AuditData as RawAuditData, AuditType},
        policy::bitflags::{
            Capability as CapabilityBitflag, FilePermission as FilePermissionBitflag,
            PolicyDecision as PolicyDecisionBitflag, Signal as SignalBitflag,
        },
    },
    utils::byte_array_to_string,
};

use super::{
    Capability, ContainerIdentifier, DeviceAccess, FileAccess, FileIdentifier, FilePermissionSet,
    IpcAccess, IpcPermission, IpcPermissionSet, PolicyDecisionSet, PolicyIdentifier, SignalAccess,
    SignalSet,
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RuleMapping {
    pub policy: PolicyIdentifier,
    pub file: String,
    pub line_number: usize,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum AuditData {
    File(FileAccess),
    Device(DeviceAccess),
    Capability(Capability),
    Ipc(IpcAccess),
    Signal(SignalAccess),
    Socket(/* TODO */),
    ImplicitPolicy {/* TODO */},
    NewContainer,
    PolicyAssociation,
    String(String),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    comm: String,
    rule: RuleMapping,
    container: ContainerIdentifier,
    pid: u32,
    ns_pid: u32,
    decision: PolicyDecisionSet,
    data: AuditData,
}

impl TryFrom<RawAuditData> for AuditEvent {
    type Error = anyhow::Error;

    fn try_from(data: RawAuditData) -> Result<Self, Self::Error> {
        Ok(AuditEvent {
            comm: byte_array_to_string(&data.comm),
            rule: RuleMapping {
                // FIXME: This is garbage data for now
                policy: PolicyIdentifier::PolicyId(data.policy_id),
                file: "filename here".into(),
                line_number: 1337,
            },
            container: ContainerIdentifier::ContainerId(data.container_id),
            pid: data.pid,
            ns_pid: data.ns_pid,
            decision: PolicyDecisionSet::try_from(PolicyDecisionBitflag::from_bits_truncate(
                data.decision,
            ))?,
            data: match data.type_ {
                AuditType::AUDIT_TYPE_FILE => {
                    // SAFETY: This relies on the correctness of `data.type_`,
                    // which comes from the eBPF side
                    let file_data = unsafe { data.__bindgen_anon_1.file };
                    AuditData::File(FileAccess {
                        file: FileIdentifier::Inode {
                            inum: file_data.st_ino,
                            dev: file_data.st_dev,
                        },
                        access: FilePermissionSet::try_from(
                            FilePermissionBitflag::from_bits_truncate(file_data.access),
                        )?,
                    })
                }
                //AuditType::AUDIT_TYPE_DEVICE => todo!("Implement me"),
                AuditType::AUDIT_TYPE_CAP => {
                    // SAFETY: This relies on the correctness of `data.type_`,
                    // which comes from the eBPF side
                    let cap_data = unsafe { data.__bindgen_anon_1.cap };
                    AuditData::Capability(Capability::try_from(
                        CapabilityBitflag::from_bits_truncate(cap_data.cap),
                    )?)
                }
                //AuditType::AUDIT_TYPE_NET => todo!("Implement me"),
                AuditType::AUDIT_TYPE_IPC => {
                    // SAFETY: This relies on the correctness of `data.type_`,
                    // which comes from the eBPF side
                    let ipc_data = unsafe { data.__bindgen_anon_1.ipc };
                    AuditData::Ipc(IpcAccess {
                        access: IpcPermissionSet::from(match ipc_data.sender {
                            0 => IpcPermission::Receive,
                            _ => IpcPermission::Send,
                        }),
                        kind: None, // TODO
                        other: PolicyIdentifier::PolicyId(ipc_data.other_policy_id),
                    })
                }
                AuditType::AUDIT_TYPE_SIGNAL => {
                    // SAFETY: This relies on the correctness of `data.type_`,
                    // which comes from the eBPF side
                    let sig_data = unsafe { data.__bindgen_anon_1.signal };
                    AuditData::Signal(SignalAccess {
                        other: PolicyIdentifier::PolicyId(sig_data.other_policy_id),
                        signal: SignalSet::try_from(SignalBitflag::from_bits_truncate(
                            sig_data.signal,
                        ))?,
                    })
                }
                v => bail!("No audit data type corresponding to {:?}", v),
            },
        })
    }
}
