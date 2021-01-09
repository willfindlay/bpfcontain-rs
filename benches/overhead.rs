// SPDX-License-Identifier: GPL-2
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::fs::{remove_file, File};
use std::io::Write;
use std::path::Path;

use bpfcontain::bpf_program::{load_bpf_program, load_policy_str, BpfcontainSkelBuilder};
use criterion::{black_box, criterion_group, criterion_main, Criterion, PlotConfiguration};
use osbench_rs::{create_files, create_processes, create_threads};

fn bench_os_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Writes");

    group.bench_function("no bpfcontain", |b| {
        b.iter(|| create_files(Path::new("/tmp")))
    });

    let mut skel_builder = BpfcontainSkelBuilder::default();
    let skel = load_bpf_program(&mut skel_builder, false).expect("Failed to load BPF program");

    group.bench_function("bpfcontain", |b| b.iter(|| create_files(Path::new("/tmp"))));

    drop(skel);
    group.finish();
}

fn bench_procs_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Processes");
    group.bench_function("no bpfcontain", |b| b.iter(|| create_processes()));

    let mut skel_builder = BpfcontainSkelBuilder::default();
    let skel = load_bpf_program(&mut skel_builder, false).expect("Failed to load BPF program");

    group.bench_function("bpfcontain", |b| b.iter(|| create_processes()));

    drop(skel);
    group.finish();
}

fn bench_threads_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Threads");
    group.bench_function("no bpfcontain", |b| b.iter(|| create_threads()));

    let mut skel_builder = BpfcontainSkelBuilder::default();
    let skel = load_bpf_program(&mut skel_builder, false).expect("Failed to load BPF program");

    group.bench_function("bpfcontain", |b| b.iter(|| create_threads()));

    drop(skel);
    group.finish();
}

criterion_group!(
    osbench,
    bench_os_overhead,
    bench_procs_overhead,
    bench_threads_overhead
);
criterion_main!(osbench);
