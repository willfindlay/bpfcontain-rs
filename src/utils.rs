// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Context, Result};
use goblin::Object;
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

/// Locate a symbol `symbol_name` in an ELF binary represented by the Goblin
/// Elf struct `elf`.
pub fn get_symbol(elf: &goblin::elf::Elf, symbol_name: &str) -> Result<goblin::elf::Sym> {
    // Grab the symbol table and string table
    let symtab = &elf.syms;
    let strtab = &elf.strtab;

    // Locate the symbol
    let sym = symtab.iter().find(|sym| {
        if let Some(sym) = strtab.get(sym.st_name) {
            if let Ok(name) = sym {
                if name == symbol_name {
                    return true;
                }
            }
        }
        false
    });

    match sym {
        Some(sym) => Ok(sym),
        None => bail!("Failed to find symbol {}", symbol_name),
    }
}

/// Get the offset of a symbol `symbol_name` relative to .text in an ELF binary
/// located at `binary_path`.
pub fn get_symbol_offset(binary_path: &str, symbol_name: &str) -> Result<usize> {
    let path = Path::new(binary_path);
    let buffer = fs::read(path)?;

    // Parse the ELF file
    let elf = match Object::parse(&buffer)? {
        Object::Elf(elf) => elf,
        _ => bail!("Failed to parse ELF file {}", binary_path),
    };

    // Find the relative offset of symbol
    let symbol = get_symbol(&elf, symbol_name)?;
    let offset = symbol.st_value as usize;

    log::debug!("{} {}={:#0x}", binary_path, symbol_name, offset);

    Ok(offset as usize)
}

/// Returns a `(st_dev, st_ino)` pair for the path `path`.
pub fn path_to_dev_ino(path: &Path) -> Result<(u64, u64)> {
    let stat = fs::metadata(path).context(format!("Failed to look up metadata for {:?}", path))?;

    Ok((stat.st_dev(), stat.st_ino()))
}

/// Returns a vector of (st_dev, st_ino) pairs for the glob `pattern`.
pub fn glob_to_dev_ino(pattern: &str) -> Result<Vec<(u64, u64)>> {
    use glob::glob;
    let mut results = vec![];

    for entry in glob(pattern).context(format!("Failed to glob {}", pattern))? {
        if let Ok(path) = entry {
            match path_to_dev_ino(&path) {
                Ok(res) => results.push(res),
                Err(e) => log::warn!("Unable to get information for {:?}: {}", path, e),
            }
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

/// Converts an enum into its bitflags representation
pub trait ToBitflags {
    type BitFlag;
    fn to_bitflags(&self) -> Result<Self::BitFlag>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "TODO"]
    fn get_symbol_test() -> Result<()> {
        todo!()
    }

    #[test]
    #[ignore = "TODO"]
    fn get_symbol_offset_test() -> Result<()> {
        todo!()
    }
}
