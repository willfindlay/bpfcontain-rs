#!/usr/bin/env bash

# Run CI workflow locally using vagrant.
# Depends on vagrant.

set -eo pipefail

vagrant up
vagrant ssh -c "uname -a"
vagrant ssh -c "cargo build"
vagrant ssh -c "cargo clippy -- -D warnings"
vagrant ssh -c "cargo test"
