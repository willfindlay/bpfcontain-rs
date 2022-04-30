// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::{
    env,
    fs::{remove_file, File},
    io::{BufWriter, Write},
    os::unix::{fs::symlink, prelude::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

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

    generate_vmlinux();
    generate_bindings();
    generate_skeleton();
}

fn bindgen_builder() -> bindgen::Builder {
    bindgen::builder()
        .derive_default(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .clang_arg("-Isrc/bpf/include")
        .clang_arg("-Wno-unknown-attributes")
        .clang_arg("-target")
        .clang_arg("bpf")
        .ignore_functions()
}

fn generate_bindings() {
    let bindings_out = PathBuf::from(format!("{}/bindings.rs", env::var("OUT_DIR").unwrap()));
    let vmlinux_bindings_out = PathBuf::from(format!(
        "{}/vmlinux_bindings.rs",
        env::var("OUT_DIR").unwrap()
    ));

    // Generate bpfcontain api bindings
    let bindings = bindgen_builder()
        .header("bindings.h")
        .blocklist_file(".*/vmlinux.h.*")
        .constified_enum_module("policy_decision_t")
        .constified_enum_module("file_permission_t")
        .constified_enum_module("capability_t")
        .constified_enum_module("net_operation_t")
        .constified_enum_module("signal_operation_t")
        .bitfield_enum("audit_level_t")
        .generate()
        .expect("Failed to generate bpfcontain api bindings");

    // Generate int bindings from vmlinux
    let vmlinux_bindings = bindgen_builder()
        .header("bindings.h")
        .allowlist_type("s8")
        .allowlist_type("s16")
        .allowlist_type("s32")
        .allowlist_type("s64")
        .allowlist_type("u8_")
        .allowlist_type("u16_")
        .allowlist_type("u32_")
        .allowlist_type("u64_")
        .allowlist_type("bool")
        .generate()
        .expect("Failed to generate vmlinux type bindings");

    // Save bindings
    bindings
        .write_to_file(bindings_out)
        .expect("Failed to save bindings");
    vmlinux_bindings
        .write_to_file(vmlinux_bindings_out)
        .expect("Failed to save bindings");
}

fn generate_skeleton() {
    match SkeletonBuilder::new("src/bpf/bpfcontain.bpf.c")
        .clang_args("-Isrc/bpf/include -Wno-unknown-attributes")
        .generate("src/bpf/mod.rs")
    {
        Ok(_) => {}
        Err(e) => panic!("Failed to generate skeleton: {}", e),
    }
}

/// Checks if a file exists and is non-empty
fn nonempty_exists(path: &Path) -> bool {
    path.exists()
        && File::open(path)
            .and_then(|open_file| open_file.metadata())
            .map(|metadata| metadata.size() != 0)
            .unwrap_or(false)
}

fn generate_vmlinux() {
    // Determine pathname for vmlinux header
    let kernel_release = uname().expect("Failed to fetch system information").release;
    let vmlinux_path = PathBuf::from(format!("src/bpf/include/vmlinux_{}.h", kernel_release));
    let vmlinux_link_path = PathBuf::from("src/bpf/include/vmlinux.h");

    // Populate vmlinux_{kernel_release}.h with BTF info
    if !nonempty_exists(&vmlinux_path) {
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
            .expect("Failed to run bpftool");

        // Make sure we were able to run bpftool successfully
        assert!(output.status.success(), "Failed to get BTF info");
        // Make sure we actually have something to write to vmlinux.h
        assert!(
            !output.stdout.is_empty(),
            "bpftool codegen output was empty"
        );

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
}
