# Build image
FROM rust:alpine AS builder

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
    && RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack \
    && npm install rollup
# Build
COPY --chown=app:app . /app
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
