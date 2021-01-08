// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

fn main() {
    // Re-run build if our header file(s) has changed
    println!("cargo:rerun-if-changed=src/include/libbpfcontain.h");
    println!("cargo:rerun-if-changed=src/include/structs.h");

    // Generate bindings
    let bindings = bindgen::builder()
        .header("src/include/libbpfcontain.h")
        .derive_default(true)
        .generate()
        .expect("Failed to generate bindings");

    // Save bindings
    bindings
        .write_to_file("src/libbpfcontain/bindings.rs")
        .expect("Failed to save bindings");

    // Include bpfcontain as a C library
    println!("cargo:rustc-link-lib=dylib=bpfcontain");
}
