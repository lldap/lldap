# Build image
FROM rust:1.85.0-alpine3.21 AS chef

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
    && apk add openssl-dev musl-dev make perl curl gzip

USER app
WORKDIR /app

RUN set -x \
    # Install build tools
    && RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack cargo-chef \
    && rustup target add wasm32-unknown-unknown

# Prepare the dependency list.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path /tmp/recipe.json

# Build dependencies.
FROM chef AS builder
COPY --from=planner /tmp/recipe.json recipe.json
RUN cargo chef cook --release -p lldap_app --target wasm32-unknown-unknown \
    && cargo chef cook --release -p lldap \
    && cargo chef cook --release -p lldap_migration_tool \
    && cargo chef cook --release -p lldap_set_password

# Copy the source and build the app and server.
COPY --chown=app:app . .
RUN cargo build --release -p lldap -p lldap_migration_tool -p lldap_set_password \
    # Build the frontend.
    && ./app/build.sh

# Final image
FROM alpine:3.21

ENV GOSU_VERSION=1.14
# Fetch gosu from git
RUN set -eux; \
        \
        apk add --no-cache --virtual .gosu-deps \
                ca-certificates \
                dpkg \
                gnupg \
        ; \
        \
        dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
        wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
        wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
        \
# verify the signature
        export GNUPGHOME="$(mktemp -d)"; \
        gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
        gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
        command -v gpgconf && gpgconf --kill all || :; \
        rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
        \
# clean up fetch dependencies
        apk del --no-network .gosu-deps; \
        \
        chmod +x /usr/local/bin/gosu; \
# verify that the binary works
        gosu --version; \
        gosu nobody true


WORKDIR /app

COPY --from=builder /app/app/index_local.html app/index.html
COPY --from=builder /app/app/static app/static
COPY --from=builder /app/app/pkg app/pkg
COPY --from=builder /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password ./
COPY docker-entrypoint.sh lldap_config.docker_template.toml ./
COPY scripts/bootstrap.sh ./

RUN set -x \
    && apk add --no-cache bash tzdata \
    && for file in $(cat app/static/libraries.txt); do wget -P app/static "$file"; done \
    && for file in $(cat app/static/fonts/fonts.txt); do wget -P app/static/fonts "$file"; done \
    && chmod a+r -R .

ENV LDAP_PORT=3890
ENV HTTP_PORT=17170

EXPOSE ${LDAP_PORT} ${HTTP_PORT}

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["run", "--config-file", "/data/lldap_config.toml"]
HEALTHCHECK CMD ["/app/lldap", "healthcheck", "--config-file", "/data/lldap_config.toml"]
