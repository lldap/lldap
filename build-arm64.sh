#!/bin/bash
wget -c https://musl.cc/aarch64-linux-musl-cross.tgz
tar zxf ./aarch64-linux-musl-cross.tgz -C /opt
rm ./aarch64-linux-musl-cross.tgz
export RUST_BACKTRACE=1
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
export RUSTFLAGS="-Ctarget-feature=+crt-static"
export PATH="/opt/aarch64-linux-musl-cross/:/opt/aarch64-linux-musl-cross/bin/:$PATH"
rustup target add aarch64-unknown-linux-musl
cargo build --target=aarch64-unknown-linux-musl --release -p lldap -p migration-tool
