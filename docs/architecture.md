# Architecture

The server is entirely written in Rust, using [actix](https://actix.rs) for the
backend and [yew](https://yew.rs) for the frontend.

Backend:
* Listens on a port for LDAP protocol.
  * Only a small, read-only subset of the LDAP protocol is supported.
  * In addition to that, an extension to allow resetting the password is also
    supported.
* Listens on another port for HTTP traffic.
  * The authentication API, based on JWTs, is under "/auth".
  * The user management API is a GraphQL API under "/api/graphql". The schema
    is defined in `schema.graphql`.
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
* The main SQL DBs are supported: SQLite by default, MySQL, MariaDB, PostgreSQL
  (see [./database_migration.md](DB Migration) for how to migrate off of
  SQLite).

### Code organization

* `auth/`: Contains the shared structures needed for authentication, the
  interface between front and back-end. In particular, it contains the OPAQUE
  structures and the JWT format.
* `app/`: The frontend.
  * `src/components`: The elements containing the business and display logic of
    the various pages and their components.
  * `src/infra`: Various tools and utilities.
* `server/`: The backend.
  * `src/domain/`: Domain-specific logic: users, groups, checking passwords...
  * `src/infra/`: API, both GraphQL and LDAP

## Authentication

### Passwords

Authentication is done via the OPAQUE protocol, meaning that the passwords are
never sent to the server, but instead the client proves that they know the
correct password (zero-knowledge proof). This is likely overkill, especially
considered that the LDAP interface requires sending the password to the server,
but it's one less potential flaw (especially since the LDAP interface can be
restricted to an internal docker-only network while the web app is exposed to
the Internet).

OPAQUE's "passwords" (user-specific blobs of data that can only be used in a
zero-knowledge proof that the password is correct) are hashed using Argon2, the
state of the art in terms of password storage. They are hashed using a secret
provided in the configuration (which can be given as environment variable or
command line argument as well): this should be kept secret and shouldn't change
(it would invalidate all passwords). Note that even if it was compromised, the
attacker wouldn't be able to decrypt the passwords without running an expensive
brute-force search independently for each password.

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

