# BPFContain

BPFContain is a container security daemon for GNU/Linux leveraging the power and
safety of eBPF and Rust.

## About

### Why BPFContain?

TODO

### Why eBPF?

TODO

### Why Rust?

TODO

### Citing

TODO

## Installation

TODO

## Usage

TODO

## Contributing

TODO

## Todo List

* Choose a good yaml crate
    * Candidates: [`serde-yaml`](https://docs.rs/serde_yaml/0.8.14/serde_yaml/)
      and [`yaml-rust`](https://docs.rs/yaml-rust/0.4.4/yaml_rust/)
* Implement parsing container policy
    * Document policy language
* Add virtualization support
    * should probably be OCI-compliant
    * can integrate with policy (e.g. mount policy with overlayfs can replace file/filesystem policy entirely)
