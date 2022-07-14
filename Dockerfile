# Create our development image
FROM rust:1.62-slim-bullseye AS builder-base

# Set env for our builder
ENV CARGO_TERM_COLOR="always" \
    RUSTFLAGS="-Ctarget-feature=-crt-static" \
    OPENSSL_INCLUDE_DIR="/usr/include/openssl/" \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER="arm-linux-gnueabihf-gcc" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"

# Get develop package and npm
RUN apt update && \
    apt install -y --no-install-recommends curl git wget libssl-dev build-essential make perl pkg-config && \
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt update && \
    apt install -y --no-install-recommends nodejs && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* && \
    npm install -g npm && \
    npm install -g yarn && \
    npm install -g pnpm 

#######################################################
### Only enable if building non-native architecture ###
#######################################################
## aarch64 build 
### Set openssl path
#ENV OPENSSL_LIB_DIR="/usr/lib/aarch64-linux-gnu/"
#RUN dpkg --add-architecture arm64 && \
#    apt update && \
#    apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross libssl-dev:arm64 && \
#    apt clean && \
#    rm -rf /var/lib/apt/lists/*
### add arm64 target
#RUN rustup target add aarch64-unknown-linux-gnu

## armhf build
### Set openssl path
#ENV OPENSSL_LIB_DIR="/usr/lib/arm-linux-gnueabihf/"
#RUN dpkg --add-architecture armhf && \
#    apt update && \
#    apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-armhf-cross libc6-dev-armhf-cross libssl-dev:armhf && \
#    apt clean && \
#    rm -rf /var/lib/apt/lists/*
### add armhf target
#RUN rustup target add rustup target add armv7-unknown-linux-gnueabihf


# Install cargo-chef and wasm-pack via cargo [npm doesn't have arm64 bin]    
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo install cargo-chef wasm-pack
RUN rustup target add wasm32-unknown-unknown
# Install rollup
RUN npm install -g rollup


# Prepare dependencies
FROM builder-base AS planner
WORKDIR /lldap-src
COPY . .
RUN cargo chef prepare --recipe-path /tmp/recipe.json

# Build depedencies
FROM builder-base AS builder
COPY --from=planner /tmp/recipe.json recipe.json
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo chef cook --release -p migration-tool
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo chef cook --release -p lldap_app --target wasm32-unknown-unknown
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo chef cook --release -p lldap
WORKDIR /lldap-src
COPY . .

# Compiling application, take your time
### amd64
#RUN cargo build --target=x86_64-unknown-linux-gnu --release -p lldap -p migration-tool
#######################################################
### Only enable if building non-native architecture ###
#######################################################
### arm64
RUN cargo build --target=aarch64-unknown-linux-gnu --release -p lldap -p migration-tool
### armhf
#RUN cargo build --target=armv7-unknown-linux-gnueabihf --release -p lldap -p migration-tool


### Build frontend
RUN app/build.sh
# Prepare our application path
RUN mkdir -p /lldap/app
# Web and App dir
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY lldap_config.docker_template.toml /lldap/
# The applications
RUN cp target/*/release/lldap /lldap/lldap && \
    cp target/*/release/migration-tool /lldap/migration-tool && \
    cp -R app/index.html \
          app/pkg \
          app/static \
          /lldap/app/
# Fetch our fonts
WORKDIR /lldap
RUN set -x \
    && for file in $(cat /lldap/app/static/libraries.txt); do wget -P app/static "$file"; done \
    && for file in $(cat /lldap/app/static/fonts/fonts.txt); do wget -P app/static/fonts "$file"; done \
    && chmod a+r -R .



### Final image
FROM alpine:3.16
WORKDIR /app
ENV UID=1000 \
    GID=1000 \
    USER=lldap
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    apk add --no-cache tini ca-certificates bash gosu && \
    addgroup -g $GID $USER && \
    adduser \
    --disabled-password \
    --gecos "" \
    --home "$(pwd)" \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER" && \
    mkdir -p /data && \
    chown $USER:$USER /data
### Copy out the binary and web from builder
COPY --from=builder --chown=$USER:$USER /lldap /app
COPY --from=builder --chown=$USER:$USER /docker-entrypoint.sh /docker-entrypoint.sh
VOLUME ["/data"]
WORKDIR /app
ENTRYPOINT ["tini", "--", "/docker-entrypoint.sh"]
#CMD ["run", "--config-file", "/data/lldap_config.toml"]
