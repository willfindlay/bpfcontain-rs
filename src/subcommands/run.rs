// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};
use clap::ArgMatches;
use std::fs::File;
use std::io::Read;

use crate::libbpfcontain::containerize;

pub fn main(args: &ArgMatches) -> Result<()> {
    containerize(42)
}
