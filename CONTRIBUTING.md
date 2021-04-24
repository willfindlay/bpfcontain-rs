# Contributing to BPFContain

Contributions are welcome, appreciated, and encouraged. See [Getting Started](#getting-started) for an overview of the project and some suggestions for new contributors, and [the Wish List](#wish-list) for a list of things that can use some work.

# Getting Started

New contributors can refer to this section to get familiar with the project and for suggestions on what to work on.

## Technologies

BPFContain relies on the following technologies. You should try to familiarize yourself with them.

- The Rust programming language
- libbpf and libbpf-rs
- eBPF and its flavour of the C programming language
- The Linux kernel

## Dependencies

BPFContain depends on a number of Rust crates, which are listed in its [Cargo.toml](Cargo.toml). It also requires at least Linux 5.11 compiled with BTF debugging symbols and support for BPF LSM hooks.

## Suggestions for New Contributors

If you're a new contributor, consider working on the following. You can also refer to [the Wish List](#wish-list) for a list of things that need work.

- Documentation (eBPF and Rust source code, along with the BPFContain policy language)
- Sample policy in [/examples](examples)
- Writing unit tests
- Any issues labelled with "Good First Issue"

# Wish List

This section suggests some items that need work.

## Easy

- [ ] Write missing documentation (eBPF and Rust code)
- [ ] Documentation for the BPFContain policy language

## Medium

- [ ] Write more sample policies
- [ ] Write unit tests

## Hard

- [ ] Write integration tests to test BPFContain policy enforcement
- [ ] Docker support (dedicated issue for this coming soon)
- [ ] Support for IP allow/denylist policies using TC eBPF programs
