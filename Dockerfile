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
        app
RUN set -x \
    # Install required packages
    && apk add npm openssl-dev musl-dev make perl
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
USER root
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release -p lldap --recipe-path recipe.json \
  && cargo chef cook --release -p lldap_app --target wasm32-unknown-unknown

# Copy the source and build the app.
COPY --chown=app:app . .
RUN cargo build --release -p lldap
# TODO: release mode.
RUN ./app/build.sh

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
        app

RUN mkdir /data && chown app:app /data
USER app
WORKDIR /app
COPY --chown=app:app --from=builder /app/app/index.html app/index.html
COPY --chown=app:app --from=builder /app/app/main.js app/main.js
COPY --chown=app:app --from=builder /app/app/pkg app/pkg
COPY --chown=app:app --from=builder /app/target/release/lldap lldap

ENV LDAP_PORT=3890
ENV HTTP_PORT=17170

EXPOSE ${LDAP_PORT} ${HTTP_PORT}

CMD ["/app/lldap", "run", "--config-file", "/data/lldap_config.toml"]
