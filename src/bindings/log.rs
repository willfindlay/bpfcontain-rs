// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Structs for logging messages from BPF.

use plain::Plain;

use super::raw;

pub type LogMsg = raw::BPFContainLog;
unsafe impl Plain for LogMsg {}

pub type LogLevel = raw::LogLevel;
