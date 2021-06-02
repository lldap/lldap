# lldap - Light LDAP implementation for authentication

This project is an lightweight authentication server that provides an
opinionated, simplified LDAP interface for authentication: clients that can
only speak LDAP protocol can talk to it and use it as an authentication server.

The goal is _not_ to provide a full LDAP server; if you're interested in that,
check out OpenLDAP. This server is made to be:
* simple to setup (no messing around with `slapd`)
* simple to manage (friendly web UI)
* opinionated with basic defaults so you don't have to understand the
  subtleties of LDAP.

It mostly targets self-hosting servers, with open-source components like
Nextcloud, Airsonic and so on that only support LDAP as a source of external
authentication.

## Architecture

The server is entirely written in Rust, using [actix](https://actix.rs) and
[yew](https://yew.rs) for the frontend.

Backend:
* Listens on a port for LDAP protocol.
  * Only a small, read-only subset of the LDAP protocol is supported.
* Listens on another port for HTTP traffic.
  * The authentication API, based on JWTs, is under "/auth".
  * The user management API is under "/api" (POST requests only).
  * The static frontend files are served by this port too.

Note that secure protocols (LDAPS, HTTPS) are currently not supported. This can
be worked around by using a reverse proxy in front of the server (for the HTTP
API) that wraps/unwraps the HTTPS messages, or only open the service to
localhost or other trusted docker containers (for the LDAP API).

Frontend:
* User management UI.
* Written in Rust compiled to WASM as an SPA with the Yew library.
* Based on components, with a React-like organization.

Data storage:
* The data (users, groups, memberships, active JWTs, ...) is stored in SQL.
* Currently only SQLite is supported (see
  https://github.com/launchbadge/sqlx/issues/1225 for what blocks us from
  supporting more SQL backends).

### Code organization

* `model/`: Contains the shared data, the interface between front and back-end.
  The data is transferred by being serialized to JSON, for compatibility with
  other HTTP-based clients.
* `app/`: The frontend.
* `src/`: The backend.
  * `domain/`: Domain-specific logic: users, groups, checking passwords...
  * `infra/`: API, both HTTP and LDAP

## Authentication

### Passwords

Passwords are hashed using Argon2, the state of the art in terms of password
storage. They are hashed using a secret provided in the configuration (which
can be given as environment variable or command line argument as well): this
should be kept secret and shouldn't change (it would invalidate all passwords).

TODO: Add client-side password hashing.

### JWTs and refresh tokens

When logging in for the first time, users are provided with a refresh token
that gets stored in an HTTP-only cookie, valid for 30 days. They can use this
token to get a JWT to get access to various servers: the JWT lists the groups
the user belongs to. To simplify the setup, there is a single JWT secret that
should be shared between the authentication server and the application servers;
and users don't get a different token per application server
(this could be implemented, we just didn't have any use case yet).

JWTs are only valid for one day: when they expire, a new JWT can be obtained
from the authentication server using the refresh token. If the user stays
logged in, they would only have to type their password once a month.

#### Logout

In order to handle logout correctly, we rely on a blacklist of JWTs. When a
user logs out, their refresh token is removed from the backend, and all of
their currently valid JWTs are added to a blacklist. Incoming requests are
checked against this blacklist (in-memory, faster than calling the database).
Applications that want to use these JWTs should subscribe to be notified of
blacklisted JWTs (TODO: implement the PubSub service and API).

## Contributions

Contributions are welcome! Just fork and open a PR. Or just file a bug.

We don't have a code of conduct, just be respectful and remember that it's just
normal people doing this for free on their free time.

Make sure that you run `cargo fmt` in each crate that you modified (top-level,
`app/` and `model/`) before creating the PR.

### Setup

To bring up the server, you'll need to compile the frontend. In addition to
cargo, you'll need:

* WASM-pack: `cargo install wasm-pack`
* rollup.js: `npm install rollup`

Then you can build the frontend files with `./app/build.sh` (you'll need to run
this after every front-end change to update the WASM package served).

To bring up the server, just run `cargo run`. The default config is in
`src/infra/configuration.rs`, but you can override it by creating an
`lldap_config.toml`, setting environment variables or passing arguments to
`cargo run`.
