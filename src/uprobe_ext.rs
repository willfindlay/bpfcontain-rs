// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Extensions for libbpf-rs uprobe functionality. Specifically, we add a higher level
//! interface for resolving symbols from ELF binaries for uprobe attachment as well as
//! attaching uprobes to a function address in our current address space.

use std::fs::read;
use std::path::Path;

use anyhow::{bail, Context as _, Result};
use goblin::elf::{Elf, Sym};
use procfs::process::Process;

/// Resolves symbols from an ELF file
/// Based on https://github.com/ingraind/redbpf/blob/main/redbpf/src/symbols.rs
struct SymbolResolver<'a> {
    elf: Elf<'a>,
}

impl<'a> SymbolResolver<'a> {
    /// Find a symbol offset within a file specified by `pathname`
    pub fn find_in_file(pathname: &Path, symbol: &str) -> Result<Option<usize>> {
        let bytes = read(pathname).context("Failed to read ELF")?;
        let resolver = Self::parse(&bytes).context("Failed to parse ELF")?;
        let offset = resolver.find_offset(symbol);
        Ok(offset)
    }

    /// Parse an ELF file and return a [`SymbolResolver`]
    pub fn parse(bytes: &[u8]) -> Result<SymbolResolver> {
        let elf = Elf::parse(bytes)?;
        Ok(SymbolResolver { elf })
    }

    /// Resolve a symbol in the ELF file
    fn resolve_sym(&self, symbol: &str) -> Option<Sym> {
        self.elf.syms.iter().find(|sym| {
            self.elf
                .strtab
                .get(sym.st_name)
                .and_then(|sym| sym.ok())
                .map(|sym| sym == symbol)
                .unwrap_or(false)
        })
    }

    /// Find the offset of a symbol in the ELF file
    pub fn find_offset(&self, symbol: &str) -> Option<usize> {
        self.resolve_sym(symbol).map(|sym| sym.st_value as usize)
    }
}

pub trait FindSymbolUprobeExt {
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link>;

    fn attach_uprobe_addr(
        &mut self,
        retprobe: bool,
        pid: i32,
        addr: usize,
    ) -> Result<libbpf_rs::Link>;
}

impl FindSymbolUprobeExt for libbpf_rs::Program {
    /// Attach a uprobe to a symbol within another binary.
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link> {
        // Find symbol in the ELF file
        let offset = SymbolResolver::find_in_file(pathname, symbol)
            .context("Error finding symbol")?
            .context("Failed to find symbol")?;

        // Explicitly null terminate pathname
        // TODO: file bug report in libbpf_rs
        let mut pathname = String::from(
            pathname
                .to_str()
                .context("Failed to convert pathname to string")?,
        );
        pathname.push_str("\0");

        // Use the offset we found to attach the probe
        Ok(self
            .attach_uprobe(retprobe, pid, pathname, offset)
            .context("Failed to attach uprobe")?)
    }

    /// Attach a uprobe to an address within our own address space.
    fn attach_uprobe_addr(
        &mut self,
        retprobe: bool,
        pid: i32,
        addr: usize,
    ) -> Result<libbpf_rs::Link> {
        // Find the offset
        let base_addr = get_base_addr()?;
        let offset = addr - base_addr;

        // Explicitly null terminate pathname
        // TODO: file bug report in libbpf_rs
        let mut pathname = "/proc/self/exe".to_string();
        pathname.push_str("\0");

        // Use the offset we found to attach the probe
        Ok(self
            .attach_uprobe(retprobe, pid, pathname, offset)
            .context("Failed to attach uprobe")?)
    }
}

/// Find our base load address. We use /proc/self/maps for this.
fn get_base_addr() -> Result<usize> {
    let me = Process::myself().context("Failed to find procfs entry")?;
    let maps = me.maps().context("Failed to get maps")?;

    for entry in maps {
        if entry.perms.contains("r-xp") {
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }

    bail!("Failed to find executable region")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_base_addr_smoke_test() {
        get_base_addr().expect("Calling get_base_addr failed");
    }
}
