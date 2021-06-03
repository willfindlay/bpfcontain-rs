// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Various utility functions.

use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use glob::glob;

/// Bump the rlimit for memlock up to full capacity.
/// This is required to load even reasonably sized eBPF maps.
///
/// Borrowed this function from [the libbpf-rs
/// docs](https://github.com/libbpf/libbpf-rs/blob/master/examples/runqslower/src/main.rs).
pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

/// Returns a `(st_dev, st_ino)` pair for the path `path`.
pub fn path_to_dev_ino(path: &Path) -> Result<(u64, u64)> {
    let stat = fs::metadata(path).context(format!("Failed to look up metadata for {:?}", path))?;

    Ok((stat.st_dev(), stat.st_ino()))
}

/// Returns a vector of (st_dev, st_ino) pairs for the glob `pattern`.
pub fn glob_to_dev_ino(pattern: &str) -> Result<Vec<(u64, u64)>> {
    let mut results = vec![];

    for path in glob(pattern)
        .context(format!("Failed to glob {}", pattern))?
        .flatten()
    {
        match path_to_dev_ino(&path) {
            Ok(res) => results.push(res),
            Err(e) => log::warn!("Unable to get information for {:?}: {}", path, e),
        }
    }

    Ok(results)
}

/// Get path relative to the current project
pub fn get_project_path<P: AsRef<Path>>(path: P) -> PathBuf {
    Path::new(file!())
        .parent()
        .expect("Failed to get parent")
        .join("..")
        .join(path)
        .canonicalize()
        .expect("Failed to canonicalize path")
}
