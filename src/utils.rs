// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Various utility functions.

use std::{
    fs,
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use glob::glob;
use log::Level;

use crate::log::log_error;

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
            Err(e) => log_error(
                e.context(format!(
                    "Unable to get device information for {}",
                    path.display()
                )),
                Some(Level::Warn),
            ),
        }
    }

    Ok(results)
}

/// Get path relative to the current project
pub fn get_project_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let project_path = Path::new(file!()).parent().expect("Failed to get parent");
    project_path
        .join("..")
        .join(path)
        .canonicalize()
        .expect("Failed to canonicalize path")
}

/// Convert a null terminated byte array to a string, discarding all trailing null
/// characters
pub fn byte_array_to_string(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.trim_matches(char::from(0)).into()
}

/// Returns false. Used for `#[serde(default = "default_false")]`
pub fn default_false() -> bool {
    false
}

/// Returns true. Used for `#[serde(default = "default_true")]`
pub fn default_true() -> bool {
    true
}
