// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use super::RuleDispatch;
use crate::{
    bindings::raw::{file_policy_key_t, file_policy_val_t},
    policy::types::FileAccess,
};

impl RuleDispatch for FileAccess {
    type Key = file_policy_key_t;
    type Value = file_policy_val_t;

    fn key(&self, policy: &crate::policy::Policy) -> anyhow::Result<Self::Key> {
        todo!()
    }

    fn value(&self) -> anyhow::Result<Self::Value> {
        todo!()
    }

    fn map<'a>(&self, maps: &'a mut crate::bpf::BpfcontainMapsMut) -> &'a mut libbpf_rs::Map {
        todo!()
    }
}
