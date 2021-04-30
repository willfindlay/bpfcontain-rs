// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

#![cfg(test)]

use std::sync::Mutex;

use lazy_static::lazy_static;
use libbpf_rs::RingBuffer;

use bpfcontain::bpf::BpfcontainSkel;
use bpfcontain::bpf_program::initialize_bpf;
use bpfcontain::policy::load_policy_recursive;
use bpfcontain::utils::get_project_path;

lazy_static! {
    static ref BPF: Mutex<BpfWrapper> = Mutex::new(init());
}

struct BpfWrapper(BpfcontainSkel<'static>, RingBuffer);

unsafe impl Send for BpfWrapper {}
unsafe impl Sync for BpfWrapper {}

fn init<'a>() -> BpfWrapper {
    let (mut skel, ringbuf) = initialize_bpf().expect("Failed to load BPF program");

    load_policy_recursive(&mut skel, get_project_path("examples").to_str().unwrap())
        .expect("Failed to load policy");

    BpfWrapper(skel, ringbuf)
}

#[test]
#[ignore = "TODO"]
fn test_untainted() {
    todo!()
}

#[test]
#[ctor::ctor]
/// Build driver for integration tests
fn build_driver() {
    use std::process::Command;

    let status = Command::new("make")
        .current_dir("tests/driver")
        .status()
        .expect("Failed to run make");
    assert!(status.success());
}
