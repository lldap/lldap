# Build image
FROM rust:alpine AS chef

RUN set -x \
    # Add user
    && addgroup --gid 10001 app \
    && adduser --disabled-password \
        --gecos '' \
        --ingroup app \
        --home /app \
        --uid 10001 \
        app \
    # Install required packages
    && apk add npm openssl-dev musl-dev make perl curl

USER app
WORKDIR /app

RUN set -x \
    # Install build tools
    && RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack cargo-chef \
    && npm install rollup \
    && rustup target add wasm32-unknown-unknown

# Prepare the dependency list.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path /tmp/recipe.json

# Build dependencies.
FROM chef AS builder
COPY --from=planner /tmp/recipe.json recipe.json
RUN cargo chef cook --release -p lldap_app --target wasm32-unknown-unknown \
    && cargo chef cook --release -p lldap

# Copy the source and build the app and server.
COPY --chown=app:app . .
RUN cargo build --release -p lldap \
    # Build the frontend.
    && ./app/build.sh

# Final image
FROM alpine

RUN set -x \
    # Add user
    && addgroup --gid 10001 app \
    && adduser --disabled-password \
        --gecos '' \
        --ingroup app \
        --home /app \
        --uid 10001 \
        app \
    # Create the /data folder
    && mkdir /data && chown app:app /data

USER app
WORKDIR /app

COPY --chown=app:app --from=builder /app/app/index.html /app/app/main.js app/
COPY --chown=app:app --from=builder /app/app/pkg app/pkg
COPY --chown=app:app --from=builder /app/target/release/lldap lldap

ENV LDAP_PORT=3890
ENV HTTP_PORT=17170

EXPOSE ${LDAP_PORT} ${HTTP_PORT}

CMD ["/app/lldap", "run", "--config-file", "/data/lldap_config.toml"]
