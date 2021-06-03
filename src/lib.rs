// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Library functions for BPFContain.

pub mod bpf;
pub mod bpf_program;
pub mod config;
pub mod log;
pub mod policy;
pub mod subcommands;
pub mod utils;

mod api;
mod bindings;
mod ns;
mod uprobe_ext;
mod uprobes;

pub use uprobes::containerize;
