// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 3, 2020  William Findlay  Created this.

use std::fs::{create_dir_all, File};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::thread;

use bpfcontain::containerize;
use bpfcontain::policy::Policy;
use lazy_static::lazy_static;

use crate::helpers::BpfcontainContextWrapper;

lazy_static! {
    static ref BPFCONTAIN: BpfcontainContextWrapper = BpfcontainContextWrapper::new();
}

/// Set up test files
#[ctor::ctor]
fn setup_files() {
    let path = PathBuf::from_str("/tmp/bpfcontain").unwrap();
    create_dir_all(path.clone()).expect("Failed to create test path");

    File::create(path.join("fileA")).unwrap();
    File::create(path.join("fileB")).unwrap();
    File::create(path.join("fileC")).unwrap();
}

/// Consume ringbuf to ensure no audit data leaks from tests
#[ctor::dtor]
fn consume_ringbuf() {
    BPFCONTAIN.consume_ringbuf();
}

#[test]
#[ignore = "TODO"]
fn test_policy_unload() {
    todo!()
}

#[test]
fn test_taints() {
    let policy = Policy::from_str(
        "
        name: test_taints
        defaultTaint: false

        restrictions:
            - file:
                path: /tmp/bpfcontain/fileB
                access: r

        taints:
            - file:
                path: /tmp/bpfcontain/fileC
                access: r
        ",
    )
    .expect("Failed to parse policy");

    BPFCONTAIN
        .load_policy(&policy)
        .expect("Failed to load policy");

    let (tx, rx) = channel();
    tx.send(policy.clone()).unwrap();

    let handler = thread::spawn(move || {
        containerize(&rx.recv().unwrap()).unwrap();
        // fileA should be fine while untainted
        File::open("/tmp/bpfcontain/fileA").unwrap();
        // fileB should always be off limits
        File::open("/tmp/bpfcontain/fileB").unwrap_err();
        // Taint the process
        File::open("/tmp/bpfcontain/fileC").unwrap();
        // Now fileA should be off limits
        File::open("/tmp/bpfcontain/fileA").unwrap_err();
    });
    handler.join().unwrap();

    // We should be able to open the files just fine in our main thread
    File::open("/tmp/bpfcontain/fileA").unwrap();
    File::open("/tmp/bpfcontain/fileB").unwrap();
    File::open("/tmp/bpfcontain/fileC").unwrap();

    BPFCONTAIN
        .unload_policy(&policy)
        .expect("Failed to unload policy");
}

#[test]
fn test_complain() {
    let policy = Policy::from_str(
        "
        name: test_complain
        defaultTaint: true
        complain: true

        restrictions:
            - file:
                path: /tmp/bpfcontain/fileA
                access: r
        ",
    )
    .expect("Failed to parse policy");

    BPFCONTAIN
        .load_policy(&policy)
        .expect("Failed to load policy");

    let (tx, rx) = channel();
    tx.send(policy.clone()).unwrap();

    let handler = thread::spawn(move || {
        containerize(&rx.recv().unwrap()).unwrap();

        // Even though fileA should be denied explicitly and fileB should be denied
        // implicitly, both should be fine because we are in complaining mode
        File::open("/tmp/bpfcontain/fileA").unwrap();
        File::open("/tmp/bpfcontain/fileB").unwrap();
    });
    handler.join().unwrap();

    BPFCONTAIN
        .unload_policy(&policy)
        .expect("Failed to unload policy");
}
