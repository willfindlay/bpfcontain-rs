// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Various uprobes that we can use to interact with BPFContain's BPF programs.

/// Uprobe attachment point for `containerize`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn do_containerize(_retp: *mut i32, _policy_id: u64) {}

#[no_mangle]
#[inline(never)]
pub extern "C" fn do_apply_policy_to_container(_retp: *mut i32, _pid: u64,_policy_id: u64) {}
