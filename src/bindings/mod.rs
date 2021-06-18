// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Bindings for BPF data structures.

pub mod audit;
pub mod policy;
pub mod state;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
// FIXME: This is related to https://github.com/rust-lang/rust-bindgen/issues/1651
// When this gets fixed in bindgen, we can remove this.
#[allow(deref_nullptr)]
#[allow(unaligned_references)]
mod raw {
    use std::env;
    use std::include;
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
