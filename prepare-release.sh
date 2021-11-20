#! /bin/sh

set -e
set -x

# Build the binary server, for x86_64.
cargo build --release -p lldap

cargo install cross
cross build --target=armv7-unknown-linux-musleabihf -p lldap --release

# Build the frontend.
./app/build.sh

VERSION=$(git describe --tags)

mkdir -p /tmp/release/x86_64
cp target/release/lldap /tmp/release/x86_64
cp -R app/index.html app/main.js app/pkg lldap_config.docker_template.toml README.md LICENSE /tmp/release/x86_64
tar -czvf lldap-x86_64-${VERSION}.tar.gz /tmp/release/x86_64

mkdir -p /tmp/release/armv7
cp target/armv7-unknown-linux-musleabihf/release/lldap /tmp/release/armv7
cp -R app/index.html app/main.js app/pkg lldap_config.docker_template.toml README.md LICENSE /tmp/release/armv7
tar -czvf lldap-armv7-${VERSION}.tar.gz /tmp/release/armv7
