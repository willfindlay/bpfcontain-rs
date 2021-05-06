// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::process::Command;

fn main() {
    // Re-run build if bpfcontain.bpf.c has changed
    println!("cargo:rerun-if-changed=src/bpf/bpfcontain.bpf.c");
    // Re-run build if our header files have changed
    println!("cargo:rerun-if-changed=bindings.h");
    for path in glob::glob("src/bpf/include/*.h")
        .expect("Failed to glob headers")
        .filter_map(Result::ok)
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Generate bindings
    let bindings = bindgen::builder()
        .header("bindings.h")
        .derive_default(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .generate()
        .expect("Failed to generate bindings");

    // Save bindings
    bindings
        .write_to_file("src/bindings/generated/generated.rs")
        .expect("Failed to save bindings");

    // Make vmlinux if we don't have a good enough version
    // TODO: This command can be allowed to fail if we already have an existing vmlinux.h
    let status = Command::new("make")
        .arg("vmlinux")
        .current_dir("src/bpf")
        .status()
        .expect("Failed to run make");
    assert!(status.success(), "Failed to update vmlinux.h");

    // Run cargo-libbpf-build
    let status = Command::new("cargo")
        .arg("libbpf")
        .arg("build")
        .status()
        .expect("Failed to run cargo libbpf build");
    assert!(status.success());

    // Run cargo-libbpf-gen
    let status = Command::new("cargo")
        .arg("libbpf")
        .arg("gen")
        .status()
        .expect("Failed to run cargo libbpf gen");
    assert!(status.success());
}
