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
use bpfcontain::config::Settings;
use bpfcontain::policy::Policy;

pub struct BpfcontainContextWrapper(pub Mutex<RefCell<BpfcontainContext<'static>>>);

impl BpfcontainContextWrapper {
    pub fn new() -> Self {
        let config = Settings::new(None).expect("Failed to get default settings");
        Self(Mutex::new(RefCell::new(
            BpfcontainContext::new(&config).expect("Failed to start Bpfcontain"),
        )))
    }

    pub fn load_policy(&self, policy: &Policy) -> Result<()> {
        let mut lock = self.0.lock().unwrap();
        let context = lock.get_mut();
        context.load_policy(policy)
    }

    pub fn unload_policy(&self, policy: &Policy) -> Result<()> {
        let mut lock = self.0.lock().unwrap();
        let context = lock.get_mut();
        context.unload_policy(policy)
    }

    pub fn consume_ringbuf(&self) {
        let mut lock = self.0.lock().unwrap();
        let context = lock.get_mut();
        let _ = context.ringbuf.consume();
    }
}

unsafe impl Send for BpfcontainContextWrapper {}
unsafe impl Sync for BpfcontainContextWrapper {}
