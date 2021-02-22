// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::path::Path;

use bpfcontain::bpf::BpfcontainSkelBuilder;
use bpfcontain::bpf_program::load_bpf_program;
use criterion::{criterion_group, criterion_main, Criterion};
use osbench_rs::{create_files, create_processes, create_threads};

/// Benchmark create/delete files overhead with and without bpfcontain.
fn bench_files_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Files");

    group.bench_function("no bpfcontain", |b| {
        b.iter(|| create_files(Path::new("/tmp")))
    });

    let mut skel_builder = BpfcontainSkelBuilder::default();
    let skel = load_bpf_program(&mut skel_builder, false).expect("Failed to load BPF program");

    group.bench_function("bpfcontain", |b| b.iter(|| create_files(Path::new("/tmp"))));

    // Manually drop skel here to avoid leaking into other tests
    drop(skel);
    group.finish();
}

/// Benchmark spawn/wait processes overhead with and without bpfcontain.
fn bench_procs_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Processes");
    group.bench_function("no bpfcontain", |b| b.iter(|| create_processes()));

    let mut skel_builder = BpfcontainSkelBuilder::default();
    let skel = load_bpf_program(&mut skel_builder, false).expect("Failed to load BPF program");

    group.bench_function("bpfcontain", |b| b.iter(|| create_processes()));

    // Manually drop skel here to avoid leaking into other tests
    drop(skel);
    group.finish();
}

/// Benchmark spawn/join threads overhead with and without bpfcontain.
fn bench_threads_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Threads");
    group.bench_function("no bpfcontain", |b| b.iter(|| create_threads()));

    let mut skel_builder = BpfcontainSkelBuilder::default();
    let skel = load_bpf_program(&mut skel_builder, false).expect("Failed to load BPF program");

    group.bench_function("bpfcontain", |b| b.iter(|| create_threads()));

    // Manually drop skel here to avoid leaking into other tests
    drop(skel);
    group.finish();
}

criterion_group!(
    osbench,
    bench_files_overhead,
    bench_procs_overhead,
    bench_threads_overhead
);
criterion_main!(osbench);
