# Get  rust image
FROM rust:1.62-slim-bullseye

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
    
# Install cargo wasm-pack
RUN cargo install wasm-pack && \
    npm install -g rollup

COPY . /lldap-src
WORKDIR /lldap-src
# Compiling application, take your time
RUN cargo build --release -p lldap -p migration-tool && \
    app/build.sh
# Prepare our application path
RUN mkdir -p /lldap/app
# Web and App dir
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY lldap_config.docker_template.toml /lldap/
# The applications
RUN cp target/release/lldap /lldap/ && \
    cp target/release/migration-tool /lldap/ && \
    cp -R web/index.html \
          web/pkg \
          web/static \
          /lldap/app/
# Just checking
RUN ls -al /lldap && \
    ls -al /lldap/app
# Fetch our fonts
WORKDIR /lldap
RUN set -x \
    && for file in $(cat /lldap/app/static/libraries.txt); do wget -P app/static "$file"; done \
    && for file in $(cat /lldap/app/static/fonts/fonts.txt); do wget -P app/static/fonts "$file"; done \
    && chmod a+r -R .


### aarch64 build 
#RUN dpkg --add-architecture arm64 && \
#    apt update && \
#    apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross libssl-dev:arm64 && \
#    apt clean && \
#    rm -rf /var/lib/apt/lists/*
### add arm64 target
#RUN rustup target add aarch64-unknown-linux-gnu
### armhf build
#RUN dpkg --add-architecture arm64 && \
#    apt update && \
#    apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-armhf-cross libc6-dev-armhf-cross libssl-dev:armhf && \
#    apt clean && \
#    rm -rf /var/lib/apt/lists/*
### add armhf target
#RUN rustup target add rustup target add armv7-unknown-linux-gnueabihf

CMD ["bash"]
