// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::process::Command;

fn main() {
    // Re-run build if our header file(s) has changed
    println!("cargo:rerun-if-changed=src/include/libbpfcontain.h");
    println!("cargo:rerun-if-changed=src/include/structs.h");
    println!("cargo:rerun-if-changed=src/bpf/bpfcontain.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/bpfcontain.h");
    println!("cargo:rerun-if-changed=src/bpf/kernel_defs.h");
    println!("cargo:rerun-if-changed=src/bpf/maps.h");
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");

    // Generate bindings
    let bindings = bindgen::builder()
        .header("src/include/libbpfcontain.h")
        .derive_default(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .rustified_enum("EventCategory")
        .rustified_enum("ObjectType")
        .generate()
        .expect("Failed to generate bindings");

    // Save bindings
    bindings
        .write_to_file("src/libbpfcontain/bindings.rs")
        .expect("Failed to save bindings");

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

    // Include bpfcontain as a C library
    println!("cargo:rustc-link-lib=dylib=bpfcontain");
}
