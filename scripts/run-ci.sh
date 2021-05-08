#!/usr/bin/env bash

set -eo pipefail

echo "Building..."
cargo build

echo "Running clippy lints..."
cargo clippy -- -D warnings

echo "Running rustfmt..."
cargo fmt -- --check

echo "Running tests..."
cargo test
