FROM rust:1.66

RUN apt update && \
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt update && \
    apt install -y --no-install-recommends nodejs libssl-dev musl-dev make perl curl 

RUN RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack cargo-chef \
    && npm install -g rollup \
    && rustup target add wasm32-unknown-unknown