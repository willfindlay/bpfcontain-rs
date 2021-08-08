# BPFContain

[![Continuous Integration](https://github.com/willfindlay/bpfcontain-rs/actions/workflows/ci.yml/badge.svg?branch=master&event=push)](https://github.com/willfindlay/bpfcontain-rs/actions/workflows/ci.yml)

BPFContain is a container security daemon for GNU/Linux leveraging the power and
safety of eBPF and Rust.

**Disclaimer:** BPFContain is still in active development and is not yet feature-complete. In particular: Docker support is a work in progress; the policy language may change at any time; and the enforcement engine is not optimized.

<!--
## About

### Why BPFContain?

TODO

### Why eBPF?

TODO

### Why Rust?

TODO

### Citing

TODO
-->

## Quick Start

You can try out BPFContain using [Vagrant](https://www.vagrantup.com/) along with the provided [Vagrantfile](Vagrantfile). All you need to do is install Vagrant (along with a virtualization provider like VirtualBox or KVM) and run `vagrant up && vagrant ssh`. You can run tests with `vagrant ssh -c "cargo test"`.

## How to Install

### Requirements

To compile and run BPFContain:

* __Linux kernel version >= 5.10__
    * Kernel should be compiled with __at least the following build flags__:
    ```ini
    CONFIG_BPF=y
    CONFIG_BPF_SYSCALL=y
    CONFIG_BPF_JIT=y
    CONFIG_TRACEPOINTS=y
    CONFIG_BPF_LSM=y
    CONFIG_DEBUG_INFO=y
    CONFIG_DEBUG_INFO_BTF=y
    # (Note: This can also be set in kernel arguments via your bootloader, e.g. grub)
    CONFIG_LSM="bpf"
    ```
    * Kernel should be compiled with __pahole >= 0.16__ installed to generate BTF info
* An up-to-date version of Clang and LLVM (BPFContain is tested on version 12.0 and up)
* Latest version of __stable Rust__ and __Cargo__ (`curl https://sh.rustup.rs -sSf | sh`)
* Other dependencies should be handled by Cargo

If you want/need to generate a new `vmlinux.h` (e.g. to support a non-standard kernel):

* You must install `bpftool` from your kernel sources
    * Available in [tools/bpf/bpftool](https://github.com/torvalds/linux/tree/master/tools/bpf/bpftool)
      in Linus' source tree
* The build script that comes with BPFContain should generate the correct `vmlinux.h` before compiling the BPF programs

### Installation

1. Make sure you have all the dependencies above.
1. Clone this repo: `git clone https://github.com/willfindlay/bpfcontain-rs/ && cd bpfcontain-rs`
1. Install BPFContain: `cargo install --path .`
1. Add `$HOME/.cargo/bin` to your `$PATH`

## Usage

1. Run the daemon once in the foreground to create all necessary files and directories
    * `sudo bpfcontain daemon fg`
    * Ctrl-C to stop
1. Install policy in `/var/lib/bpfcontain/policy`
1. Start the daemon:
    * `sudo bpfcontain daemon start`
1. Run confined programs:
    * `bpfcontain run <policy.yml>` where policy is the name of your policy

## Policy Language

BPFContain policy is written in YAML. You can have a look at [the example policy](examples)
or read [the policy documenation](TODO) (TODO: policy documentation).

<!--
## Contributing

TODO
-->

## Todo List

* Higher level policy rules
    * Full policy language documentation
* Add virtualization support
    * should probably be OCI-compliant
    * can integrate with policy (e.g. mount policy with overlayfs can replace file/filesystem policy entirely)
