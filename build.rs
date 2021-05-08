// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use uname::uname;

use std::fs::File;
use std::io::ErrorKind::AlreadyExists;
use std::io::{BufWriter, Write};
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    let kernel_release = uname().expect("Failed to fetch system information").release;
    let vmlinux_path = PathBuf::from(format!("src/bpf/include/vmlinux_{}.h", kernel_release));

    if !vmlinux_path.exists() {
        let mut vmlinux_writer = BufWriter::new(File::create(vmlinux_path.clone()).expect(
            &format!("Failed to open {} for writing", vmlinux_path.display()),
        ));

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

    match symlink(
        vmlinux_path.file_name().unwrap(),
        "src/bpf/include/vmlinux.h",
    ) {
        Err(ref e) if e.kind() == AlreadyExists => {}
        other => other.expect("Failed to symlink vmlinux.h"),
    };

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
