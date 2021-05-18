// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::fs::{remove_file, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use libbpf_cargo::SkeletonBuilder;
use uname::uname;

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
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .constified_enum_module("policy_decision_t")
        .constified_enum_module("file_permission_t")
        .constified_enum_module("capability_t")
        .constified_enum_module("net_operation_t")
        .bitfield_enum("audit_level_t")
        .clang_arg("-Isrc/bpf/include")
        .clang_arg("-Wno-unknown-attributes")
        .clang_arg("-target")
        .clang_arg("bpf")
        .ignore_functions()
        .generate()
        .expect("Failed to generate bindings");

    // Save bindings
    bindings
        .write_to_file("src/bindings/generated/generated.rs")
        .expect("Failed to save bindings");

    // Determine pathname for vmlinux header
    let kernel_release = uname().expect("Failed to fetch system information").release;
    let vmlinux_path = PathBuf::from(format!("src/bpf/include/vmlinux_{}.h", kernel_release));
    let vmlinux_link_path = PathBuf::from("src/bpf/include/vmlinux.h");

    // Populate vmlinux_{kernel_release}.h with BTF info
    if !vmlinux_path.exists() {
        let mut vmlinux_writer = BufWriter::new(
            File::create(vmlinux_path.clone())
                .expect("Failed to open vmlinux destination for writing"),
        );

        let output = Command::new("bpftool")
            .arg("btf")
            .arg("dump")
            .arg("file")
            .arg("/sys/kernel/btf/vmlinux")
            .arg("format")
            .arg("c")
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to run make");

        assert!(output.status.success());

        vmlinux_writer
            .write_all(&output.stdout)
            .expect("Failed to write to vmlinux.h");
    }

    // Remove existing link if it exists
    if vmlinux_link_path.exists() {
        remove_file(vmlinux_link_path.clone()).expect("Failed to unlink vmlinux.h");
    }

    // Create a new symlink
    symlink(vmlinux_path.file_name().unwrap(), vmlinux_link_path)
        .expect("Failed to symlink vmlinux.h");

    // Generate skeleton
    match SkeletonBuilder::new("src/bpf/bpfcontain.bpf.c")
        .clang_args("-Isrc/bpf/include -Wno-unknown-attributes")
        .generate("src/bpf/mod.rs")
    {
        Ok(_) => {}
        Err(e) => panic!("Failed to generate skeleton: {}", e),
    }
}
