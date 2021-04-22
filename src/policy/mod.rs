// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Rust side of BPFContain policy.

mod helpers;
mod policy;
mod rules;

pub use policy::load_policy_recursive;
pub use policy::Policy;
