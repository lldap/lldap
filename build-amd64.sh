#!/bin/bash
wget -c https://musl.cc/x86_64-linux-musl-cross.tgz
tar zxf ./x86_64-linux-musl-cross.tgz -C /opt
rm ./x86_64-linux-musl-cross.tgz
export RUST_BACKTRACE=1
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
export RUSTFLAGS="-Ctarget-feature=+crt-static"
export PATH="/opt/x86_64-linux-musl-cross/:/opt/x86_64-linux-musl-cross/bin/:$PATH"
rustup target add x86_64-unknown-linux-musl
cargo build --target=x86_64-unknown-linux-musl --release -p lldap -p migration-tool
