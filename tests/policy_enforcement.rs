// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// May 3, 2020  William Findlay  Created this.

use std::str::FromStr;

use bpfcontain::policy::Policy;
use lazy_static::lazy_static;

use crate::helpers::BpfcontainContextWrapper;

lazy_static! {
    static ref BPFCONTAIN: BpfcontainContextWrapper = BpfcontainContextWrapper::new();
}

/// Set up test files
#[ctor::ctor]
fn setup_files() {
    eprintln!("setting up files...");
}

#[test]
fn test_untainted() {
    // TODO temporary
    let policy = Policy::from_str(
        "
        name: foo
        cmd: qux
        defaultTaint: false
        ",
    )
    .expect("Failed to parse policy");

    BPFCONTAIN
        .load_policy(&policy)
        .expect("Failed to load policy");
}
