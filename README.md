<h1 align="center">lldap - Light LDAP implementation for authentication</h1>

<p align="center">
<i style="font-size:24px">LDAP made easy.</i>
</p>

<p align="center">
  <a href="https://github.com/lldap/lldap/actions/workflows/rust.yml?query=branch%3Amain">
    <img
      src="https://github.com/lldap/lldap/actions/workflows/rust.yml/badge.svg"
      alt="Build"/>
  </a>
  <a href="https://discord.gg/h5PEdRMNyP">
    <img alt="Discord" src="https://img.shields.io/discord/898492935446876200?label=discord&logo=discord" />
  </a>

  <a href="https://twitter.com/nitnelave1?ref_src=twsrc%5Etfw">
    <img
      src="https://img.shields.io/twitter/follow/nitnelave1?style=social"
      alt="Twitter Follow"/>
  </a>
  <a href="https://github.com/rust-secure-code/safety-dance/">
    <img
      src="https://img.shields.io/badge/unsafe-forbidden-success.svg"
      alt="Unsafe forbidden"/>
  </a>
  <a href="https://app.codecov.io/gh/lldap/lldap">
    <img alt="Codecov" src="https://img.shields.io/codecov/c/github/lldap/lldap" />
  </a>
  <br/>
  <a href="https://www.buymeacoffee.com/nitnelave" target="_blank">
    <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" >
  </a>
</p>

- [About](#about)
- [Installation](#installation)
  - [With Docker](#with-docker)
  - [With Kubernetes](#with-kubernetes)
  - [From a package repository](#from-a-package-repository)
  - [From source](#from-source)
    - [Backend](#backend)
    - [Frontend](#frontend)
  - [Cross-compilation](#cross-compilation)
- [Usage](#usage)
  - [Recommended architecture](#recommended-architecture)
- [Client configuration](#client-configuration)
  - [Compatible services](#compatible-services)
  - [General configuration guide](#general-configuration-guide)
  - [Sample client configurations](#sample-client-configurations)
  - [Incompatible services](#incompatible-services)
- [Migrating from SQLite](#migrating-from-sqlite)
- [Comparisons with other services](#comparisons-with-other-services)
  - [vs OpenLDAP](#vs-openldap)
  - [vs FreeIPA](#vs-freeipa)
  - [vs Kanidm](#vs-kanidm)
- [I can't log in!](#i-cant-log-in)
- [Contributions](#contributions)

## About

This project is a lightweight authentication server that provides an
opinionated, simplified LDAP interface for authentication. It integrates with
many backends, from KeyCloak to Authelia to Nextcloud and
[more](#compatible-services)!

<img
  src="https://raw.githubusercontent.com/lldap/lldap/master/screenshot.png"
  alt="Screenshot of the user list page"
  width="50%"
  align="right"
/>

It comes with a frontend that makes user management easy, and allows users to
edit their own details or reset their password by email.

The goal is _not_ to provide a full LDAP server; if you're interested in that,
check out OpenLDAP. This server is a user management system that is:

- simple to setup (no messing around with `slapd`),
- simple to manage (friendly web UI),
- low resources,
- opinionated with basic defaults so you don't have to understand the
  subtleties of LDAP.

It mostly targets self-hosting servers, with open-source components like
Nextcloud, Airsonic and so on that only support LDAP as a source of external
authentication.

For more features (OAuth/OpenID support, reverse proxy, ...) you can install
other components (KeyCloak, Authelia, ...) using this server as the source of
truth for users, via LDAP.

By default, the data is stored in SQLite, but you can swap the backend with
MySQL/MariaDB or PostgreSQL.

## Installation

### With Docker

The image is available at `lldap/lldap`. You should persist the `/data`
folder, which contains your configuration and the SQLite database (you can
remove this step if you use a different DB and configure with environment
variables only).

Configure the server by copying the `lldap_config.docker_template.toml` to
`/data/lldap_config.toml` and updating the configuration values (especially the
`jwt_secret` and `ldap_user_pass`, unless you override them with env variables).
Environment variables should be prefixed with `LLDAP_` to override the
configuration.

If the `lldap_config.toml` doesn't exist when starting up, LLDAP will use
default one. The default admin password is `password`, you can change the
password later using the web interface.

Secrets can also be set through a file. The filename should be specified by the
variables `LLDAP_JWT_SECRET_FILE` or `LLDAP_KEY_SEED_FILE`, and the file
contents are loaded into the respective configuration parameters. Note that
`_FILE` variables take precedence.

Example for docker compose:

- You can use either the `:latest` tag image or `:stable` as used in this example.
- `:latest` tag image contains recently pushed code or feature tests, in which some instability can be expected.
- If `UID` and `GID` no defined LLDAP will use default `UID` and `GID` number `1000`.
- If no `TZ` is set, default `UTC` timezone will be used.
- You can generate the secrets by running `./generate_secrets.sh`

```yaml
version: "3"

volumes:
  lldap_data:
    driver: local

services:
  lldap:
    image: lldap/lldap:stable
    ports:
      # For LDAP, not recommended to expose, see Usage section.
      #- "3890:3890"
      # For LDAPS (LDAP Over SSL), enable port if LLDAP_LDAPS_OPTIONS__ENABLED set true, look env below
      #- "6360:6360"
      # For the web front-end
      - "17170:17170"
    volumes:
      - "lldap_data:/data"
      # Alternatively, you can mount a local folder
      # - "./lldap_data:/data"
    environment:
      - UID=####
      - GID=####
      - TZ=####/####
      - LLDAP_JWT_SECRET=REPLACE_WITH_RANDOM
      - LLDAP_KEY_SEED=REPLACE_WITH_RANDOM
      - LLDAP_LDAP_BASE_DN=dc=example,dc=com
      # If using LDAPS, set enabled true and configure cert and key path
      # - LLDAP_LDAPS_OPTIONS__ENABLED=true
      # - LLDAP_LDAPS_OPTIONS__CERT_FILE=/path/to/certfile.crt
      # - LLDAP_LDAPS_OPTIONS__KEY_FILE=/path/to/keyfile.key
      # You can also set a different database:
      # - LLDAP_DATABASE_URL=mysql://mysql-user:password@mysql-server/my-database
      # - LLDAP_DATABASE_URL=postgres://postgres-user:password@postgres-server/my-database
```

Then the service will listen on two ports, one for LDAP and one for the web
front-end.

### With Kubernetes

See https://github.com/Evantage-WS/lldap-kubernetes for a LLDAP deployment for Kubernetes

You can bootstrap your lldap instance (users, groups)
using [bootstrap.sh](example_configs/bootstrap/bootstrap.md#kubernetes-job).
It can be run by Argo CD for managing users in git-opt way, or as a one-shot job.

### From a package repository

**Do not open issues in this repository for problems with third-party
pre-built packages. Report issues downstream.**

Depending on the distribution you use, it might be possible to install lldap
from a package repository, officially supported by the distribution or
community contributed.

#### Debian, CentOS Fedora, OpenSUSE, Ubuntu

The package for these distributions can be found at [LLDAP OBS](https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap).
- When using the distributed package, the default login is `admin/password`. You can change that from the web UI after starting the service.

#### Arch Linux

Arch Linux offers unofficial support through the [Arch User Repository
(AUR)](https://wiki.archlinux.org/title/Arch_User_Repository).
Available package descriptions in AUR are:

- [lldap](https://aur.archlinux.org/packages/lldap) -  Builds the latest stable version.
- [lldap-bin](https://aur.archlinux.org/packages/lldap-bin) - Uses the latest
  pre-compiled binaries from the [releases in this repository](https://github.com/lldap/lldap/releases).
  This package is recommended if you want to run lldap on a system with
  limited resources.
- [lldap-git](https://aur.archlinux.org/packages/lldap-git) - Builds the
  latest main branch code.

The package descriptions can be used
[to create and install packages](https://wiki.archlinux.org/title/Arch_User_Repository#Getting_started).
Each package places lldap's configuration file at `/etc/lldap.toml` and offers
[systemd service](https://wiki.archlinux.org/title/systemd#Using_units)
`lldap.service` to (auto-)start and stop lldap.

### From source

#### Backend

To compile the project, you'll need:

- curl and gzip: `sudo apt install curl gzip`
- Rust/Cargo: [rustup.rs](https://rustup.rs/)

Then you can compile the server (and the migration tool if you want):

```shell
cargo build --release -p lldap -p lldap_migration_tool
```

The resulting binaries will be in `./target/release/`. Alternatively, you can
just run `cargo run -- run` to run the server.

#### Frontend

To bring up the server, you'll need to compile the frontend. In addition to
`cargo`, you'll need WASM-pack, which can be installed by running `cargo install wasm-pack`.

Then you can build the frontend files with

```shell
./app/build.sh
```

(you'll need to run this after every front-end change to update the WASM
package served).

The default config is in `src/infra/configuration.rs`, but you can override it
by creating an `lldap_config.toml`, setting environment variables or passing
arguments to `cargo run`. Have a look at the docker template:
`lldap_config.docker_template.toml`.

You can also install it as a systemd service, see
[lldap.service](example_configs/lldap.service).

### Cross-compilation

Docker images are provided for AMD64, ARM64 and ARM/V7.

If you want to cross-compile yourself, you can do so by installing
[`cross`](https://github.com/rust-embedded/cross):

```sh
cargo install cross
cross build --target=armv7-unknown-linux-musleabihf -p lldap --release
./app/build.sh
```

(Replace `armv7-unknown-linux-musleabihf` with the correct Rust target for your
device.)

You can then get the compiled server binary in
`target/armv7-unknown-linux-musleabihf/release/lldap` and the various needed files
(`index.html`, `main.js`, `pkg` folder) in the `app` folder. Copy them to the
Raspberry Pi (or other target), with the folder structure maintained (`app`
files in an `app` folder next to the binary).

## Usage

The simplest way to use LLDAP is through the web front-end. There you can
create users, set passwords, add them to groups and so on. Users can also
connect to the web UI and change their information, or request a password reset
link (if you configured the SMTP client).

Creating and managing custom attributes is currently in Beta. It's not
supported in the Web UI. The recommended way is to use
[Zepmann/lldap-cli](https://github.com/Zepmann/lldap-cli), a
community-contributed CLI frontend.

LLDAP is also very scriptable, through its GraphQL API. See the
[Scripting](docs/scripting.md) docs for more info.

### Recommended architecture

If you are using containers, a sample architecture could look like this:

- A reverse proxy (e.g. nginx or Traefik)
- An authentication service (e.g. Authelia, Authentik or KeyCloak) connected to
  LLDAP to provide authentication for non-authenticated services, or to provide
  SSO with compatible ones.
- The LLDAP service, with the web port exposed to Traefik.
  - The LDAP port doesn't need to be exposed, since only the other containers
    will access it.
  - You can also set up LDAPS if you want to expose the LDAP port to the
    internet (not recommended) or for an extra layer of security in the
    inter-container communication (though it's very much optional).
  - The default LLDAP container starts up as root to fix up some files'
    permissions before downgrading the privilege to the given user. However,
    you can (should?) use the `*-rootless` version of the images to be able to
    start directly as that user, once you got the permissions right. Just don't
    forget to change from the `UID/GID` env vars to the `uid` docker-compose
    field.
- Any other service that needs to connect to LLDAP for authentication (e.g.
  NextCloud) can be added to a shared network with LLDAP. The finest
  granularity is a network for each pair of LLDAP-service, but there are often
  coarser granularities that make sense (e.g. a network for the \*arr stack and
  LLDAP).

## Client configuration

### Compatible services

Most services that can use LDAP as an authentication provider should work out
of the box. For new services, it's possible that they require a bit of tweaking
on LLDAP's side to make things work. In that case, just create an issue with
the relevant details (logs of the service, LLDAP logs with `verbose=true` in
the config).

### General configuration guide

To configure the services that will talk to LLDAP, here are the values:

- The LDAP user DN is from the configuration. By default,
  `cn=admin,ou=people,dc=example,dc=com`.
- The LDAP password is from the configuration (same as to log in to the web
  UI).
- The users are all located in `ou=people,` + the base DN, so by default user
  `bob` is at `cn=bob,ou=people,dc=example,dc=com`.
- Similarly, the groups are located in `ou=groups`, so the group `family`
  will be at `cn=family,ou=groups,dc=example,dc=com`.

Testing group membership through `memberOf` is supported, so you can have a
filter like: `(memberOf=cn=admins,ou=groups,dc=example,dc=com)`.

The administrator group for LLDAP is `lldap_admin`: anyone in this group has
admin rights in the Web UI. Most LDAP integrations should instead use a user in
the `lldap_strict_readonly` or `lldap_password_manager` group, to avoid granting full
administration access to many services.

### Sample client configurations

Some specific clients have been tested to work and come with sample
configuration files, or guides. See the [`example_configs`](example_configs)
folder for help with:

- [Airsonic Advanced](example_configs/airsonic-advanced.md)
- [Apache Guacamole](example_configs/apacheguacamole.md)
- [Apereo CAS Server](example_configs/apereo_cas_server.md)
- [Authelia](example_configs/authelia_config.yml)
- [Authentik](example_configs/authentik.md)
- [Bookstack](example_configs/bookstack.env.example)
- [Calibre-Web](example_configs/calibre_web.md)
- [Dell iDRAC](example_configs/dell_idrac.md)
- [Dex](example_configs/dex_config.yml)
- [Dokuwiki](example_configs/dokuwiki.md)
- [Dolibarr](example_configs/dolibarr.md)
- [Ejabberd](example_configs/ejabberd.md)
- [Emby](example_configs/emby.md)
- [Ergo IRCd](example_configs/ergo.md)
- [Gitea](example_configs/gitea.md)
- [GitLab](example_configs/gitlab.md)
- [Grafana](example_configs/grafana_ldap_config.toml)
- [Grocy](example_configs/grocy.md)
- [Harbor](example_configs/harbor.md)
- [Hedgedoc](example_configs/hedgedoc.md)
- [Home Assistant](example_configs/home-assistant.md)
- [Jellyfin](example_configs/jellyfin.md)
- [Jenkins](example_configs/jenkins.md)
- [Jitsi Meet](example_configs/jitsi_meet.conf)
- [Kasm](example_configs/kasm.md)
- [KeyCloak](example_configs/keycloak.md)
- [LibreNMS](example_configs/librenms.md)
- [Maddy](example_configs/maddy.md)
- [Mastodon](example_configs/mastodon.env.example)
- [Matrix](example_configs/matrix_synapse.yml)
- [Mealie](example_configs/mealie.md)
- [MinIO](example_configs/minio.md)
- [Nextcloud](example_configs/nextcloud.md)
- [Nexus](example_configs/nexus.md)
- [OCIS (OwnCloud Infinite Scale)](example_configs/ocis.md)
- [Organizr](example_configs/Organizr.md)
- [Portainer](example_configs/portainer.md)
- [PowerDNS Admin](example_configs/powerdns_admin.md)
- [Proxmox VE](example_configs/proxmox.md)
- [Radicale](example_configs/radicale.md)
- [Rancher](example_configs/rancher.md)
- [Seafile](example_configs/seafile.md)
- [Shaarli](example_configs/shaarli.md)
- [Squid](example_configs/squid.md)
- [Syncthing](example_configs/syncthing.md)
- [TheLounge](example_configs/thelounge.md)
- [Traccar](example_configs/traccar.xml)
- [Vaultwarden](example_configs/vaultwarden.md)
- [WeKan](example_configs/wekan.md)
- [WG Portal](example_configs/wg_portal.env.example)
- [WikiJS](example_configs/wikijs.md)
- [XBackBone](example_configs/xbackbone_config.php)
- [Zendto](example_configs/zendto.md)
- [Zitadel](example_configs/zitadel.md)
- [Zulip](example_configs/zulip.md)

### Incompatible services

Though we try to be maximally compatible, not every feature is supported; LLDAP
is not a fully-featured LDAP server, intentionally so.

LDAP browsing tools are generally not supported, though they could be. If you
need to use one but it behaves weirdly, please file a bug.

Some services use features that are not implemented, or require specific
attributes. You can try to create those attributes (see custom attributes in
the [Usage](#usage) section).

Finally, some services require password hashes so they can validate themselves
the user's password without contacting LLDAP. This is not and will not be
supported, it's incompatible with our password hashing scheme (a zero-knowledge
proof). Furthermore, it's generally not recommended in terms of security, since
it duplicates the places from which a password hash could leak.

In that category, the most prominent is Synology. It is, to date, the only
service that seems definitely incompatible with LLDAP.

## Migrating from SQLite

If you started with an SQLite database and would like to migrate to
MySQL/MariaDB or PostgreSQL, check out the [DB
migration docs](/docs/database_migration.md).

## Comparisons with other services

### vs OpenLDAP

[OpenLDAP](https://www.openldap.org) is a monster of a service that implements
all of LDAP and all of its extensions, plus some of its own. That said, if you
need all that flexibility, it might be what you need! Note that installation
can be a bit painful (figuring out how to use `slapd`) and people have mixed
experiences following tutorials online. If you don't configure it properly, you
might end up storing passwords in clear, so a breach of your server would
reveal all the stored passwords!

OpenLDAP doesn't come with a UI: if you want a web interface, you'll have to
install one (not that many look nice) and configure it.

LLDAP is much simpler to setup, has a much smaller image (10x smaller, 20x if
you add PhpLdapAdmin), and comes packed with its own purpose-built web UI.
However, it's not as flexible as OpenLDAP.

### vs FreeIPA

[FreeIPA](http://www.freeipa.org) is the one-stop shop for identity management:
LDAP, Kerberos, NTP, DNS, Samba, you name it, it has it. In addition to user
management, it also does security policies, single sign-on, certificate
management, linux account management and so on.

If you need all of that, go for it! Keep in mind that a more complex system is
more complex to maintain, though.

LLDAP is much lighter to run (<10 MB RAM including the DB), easier to
configure (no messing around with DNS or security policies) and simpler to
use. It also comes conveniently packed in a docker container.

### vs Kanidm

[Kanidm](https://kanidm.com) is an up-and-coming Rust identity management
platform, covering all your bases: OAuth, Linux accounts, SSH keys, Radius,
WebAuthn. It comes with a (read-only) LDAPS server.

It's fairly easy to install and does much more; but their LDAP server is
read-only, and by having more moving parts it is inherently more complex. If
you don't need to modify the users through LDAP and you're planning on
installing something like [KeyCloak](https://www.keycloak.org) to provide
modern identity protocols, check out Kanidm.

## I can't log in!

If you just set up the server, can get to the login page but the password you
set isn't working, try the following:

- (For docker): Make sure that the `/data` folder is persistent, either to a
  docker volume or mounted from the host filesystem.
- Check if there is a `lldap_config.toml` file (either in `/data` for docker
  or in the current directory). If there isn't, copy
  `lldap_config.docker_template.toml` there, and fill in the various values
  (passwords, secrets, ...).
- Check if there is a `users.db` file (either in `/data` for docker or where
  you specified the DB URL, which defaults to the current directory). If
  there isn't, check that the user running the command (user with ID 10001
  for docker) has the rights to write to the `/data` folder. If in doubt, you
  can `chmod 777 /data` (or whatever the folder) to make it world-writeable.
- Make sure you restart the server.
- If it's still not working, join the
  [Discord server](https://discord.gg/h5PEdRMNyP) to ask for help.

## Contributions

Contributions are welcome! Just fork and open a PR. Or just file a bug.

We don't have a code of conduct, just be respectful and remember that it's just
normal people doing this for free on their free time.

Make sure that you run `cargo fmt` from the root before creating the PR. And if
you change the GraphQL interface, you'll need to regenerate the schema by
running `./export_schema.sh`.

Join our [Discord server](https://discord.gg/h5PEdRMNyP) if you have any
questions!
