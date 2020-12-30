// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use anyhow::{bail, Result};
use goblin::Object;
use std::fs;
use std::path::Path;

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

    // Locate the
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
    let offset = symbol.st_value + elf.entry;

    Ok(offset as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_symbol() -> Result<()> {
        todo!()
    }

    #[test]
    fn test_get_symbol_offset() -> Result<()> {
        todo!()
    }
}
