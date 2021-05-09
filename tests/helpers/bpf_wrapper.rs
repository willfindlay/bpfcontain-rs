// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 9, 2020  William Findlay  Created this.

use std::cell::RefCell;
use std::sync::Mutex;

use anyhow::Result;
use bpfcontain::bpf_program::BpfcontainContext;
use bpfcontain::policy::Policy;

pub struct BpfcontainContextWrapper(pub Mutex<RefCell<BpfcontainContext<'static>>>);

impl BpfcontainContextWrapper {
    pub fn new() -> Self {
        Self(Mutex::new(RefCell::new(
            BpfcontainContext::new().expect("Failed to start Bpfcontain"),
        )))
    }

    pub fn load_policy(&self, policy: &Policy) -> Result<()> {
        let mut lock = self.0.lock().unwrap();
        let context = lock.get_mut();
        context.load_policy(policy)
    }
}

unsafe impl Send for BpfcontainContextWrapper {}
unsafe impl Sync for BpfcontainContextWrapper {}
