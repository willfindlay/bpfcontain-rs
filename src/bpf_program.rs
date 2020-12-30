// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::Result;
use clap::ArgMatches;

use crate::bpf;
use crate::utils::bump_memlock_rlimit;

pub fn main(args: &ArgMatches) -> Result<()> {
    // Initialize the skeleton builder
    let mut skel_builder = bpf::ProgsSkelBuilder::default();
    if args.occurrences_of("v") >= 3 {
        skel_builder.obj_builder.debug(true);
    }

    // Bump memlock limit
    bump_memlock_rlimit()?;

    // Open skeleton
    let mut open_skel = skel_builder.open()?;

    // TODO: Write to skeleton sections here

    // Load skeleton
    let mut skel = open_skel.load()?;
    // TODO: Attach BPF programs
    //skel.attach()?;

    Ok(())
}
