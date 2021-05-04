// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 3, 2020  William Findlay  Created this.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

static mut BPFCONTAIN_PROCESS: Option<Child> = None;

/// Set up test files
#[ctor::ctor]
fn setup_files() {
    println!("setup files: TODO")
}

/// Run BPFContain
#[ctor::ctor]
fn setup_bpfcontain() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bpfcontain"))
        .arg("daemon")
        .arg("fg")
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to run BPFContain");

    let pipe = child.stderr.as_mut().expect("Failed to take child stderr");
    let reader = BufReader::new(pipe);

    // Wait for policy to be loaded by reading the daemon's log output
    // TODO: add a mechanism for this time time out?
    for line in reader.lines() {
        let line = line.expect("Failed to read stderr");
        if line.contains("Done loading policy!") {
            break;
        }
    }

    // SAFETY: Our module destructor simply grabs a handle to the child, tries to kill it,
    // and waits for its exit status. We assert that no other parts of the code will
    // attempt to access BPFCONTAIN_PROCESS.
    unsafe { BPFCONTAIN_PROCESS = Some(child) };
}

/// Wait for BPFContain
#[ctor::dtor]
fn teardown_bpfcontain() {
    // SAFETY: Our module destructor simply grabs a handle to the child, tries to kill it,
    // and waits for its exit status. We assert that no other parts of the code will
    // attempt to access BPFCONTAIN_PROCESS.
    let child = unsafe {
        BPFCONTAIN_PROCESS
            .as_mut()
            .expect("No value for BPFCONTAIN_PROCESS")
    };

    child.kill().expect("Failed to kill BPFContain");
    child.wait().expect("Failed to wait for BPFContain");
}

#[test]
#[ignore = "TODO"]
fn test_untainted() {
    todo!()
}
