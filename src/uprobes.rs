// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::fs::read;
use std::path::Path;

use anyhow::{Context as _, Result};
use goblin::elf::{Elf, Sym};

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
        self.resolve_sym(symbol)
            .and_then(|sym| Some(sym.st_value as usize))
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
}

impl FindSymbolUprobeExt for libbpf_rs::Program {
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
}
