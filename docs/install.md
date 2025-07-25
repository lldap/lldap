# Installing LLDAP

- [With Docker](#with-docker)
- [With Podman](#with-podman)
- [With Kubernetes](#with-kubernetes)
- [From a package repository](#from-a-package-repository)
- [With FreeBSD](#with-freebsd)
- [From source](#from-source)
  - [Backend](#backend)
  - [Frontend](#frontend)
- [Cross-compilation](#cross-compilation)

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
      - LLDAP_LDAP_USER_PASS=adminPas$word
      # If using LDAPS, set enabled true and configure cert and key path
      # - LLDAP_LDAPS_OPTIONS__ENABLED=true
      # - LLDAP_LDAPS_OPTIONS__CERT_FILE=/path/to/certfile.crt
      # - LLDAP_LDAPS_OPTIONS__KEY_FILE=/path/to/keyfile.key
      # You can also set a different database:
      # - LLDAP_DATABASE_URL=mysql://mysql-user:password@mysql-server/my-database
      # - LLDAP_DATABASE_URL=postgres://postgres-user:password@postgres-server/my-database
      # If using SMTP, set the following variables
      # - LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET=true
      # - LLDAP_SMTP_OPTIONS__SERVER=smtp.example.com
      # - LLDAP_SMTP_OPTIONS__PORT=465 # Check your smtp provider's documentation for this setting
      # - LLDAP_SMTP_OPTIONS__SMTP_ENCRYPTION=TLS # How the connection is encrypted, either "NONE" (no encryption, port 25), "TLS" (sometimes called SSL, port 465) or "STARTTLS" (sometimes called TLS, port 587).
      # - LLDAP_SMTP_OPTIONS__USER=no-reply@example.com # The SMTP user, usually your email address
      # - LLDAP_SMTP_OPTIONS__PASSWORD=PasswordGoesHere # The SMTP password
      # - LLDAP_SMTP_OPTIONS__FROM=no-reply <no-reply@example.com> # The header field, optional: how the sender appears in the email. The first is a free-form name, followed by an email between <>.
      # - LLDAP_SMTP_OPTIONS__TO=admin <admin@example.com> # Same for reply-to, optional.
```

Then the service will listen on two ports, one for LDAP and one for the web
front-end.

### With Podman

LLDAP works well with rootless Podman either through command line deployment
or using [quadlets](example_configs/podman-quadlets/). The example quadlets
include configuration with postgresql and file based secrets, but have comments
for several other deployment strategies.

### With Kubernetes

See https://github.com/Evantage-WS/lldap-kubernetes for a LLDAP deployment for Kubernetes

You can bootstrap your lldap instance (users, groups)
using [bootstrap.sh](example_configs/bootstrap/bootstrap.md#kubernetes-job).
It can be run by Argo CD for managing users in git-opt way, or as a one-shot job.

### From a package repository

**Do not open issues in this repository for problems with third-party
pre-built packages. Report issues downstream.**

Depending on the distribution you use, it might be possible to install LLDAP
from a package repository, officially supported by the distribution or
community contributed.

Each package offers a [systemd service](https://wiki.archlinux.org/title/systemd#Using_units) `lldap.service` or [rc.d_lldap](example_configs/freebsd/rc.d_lldap) `rc.d/lldap` to (auto-)start and stop lldap.<br>
When using the distributed packages, the default login is `admin/password`. You can change that from the web UI after starting the service.

<details>
<summary><b>Arch Linux</b></summary>
<br>
  Arch Linux offers unofficial support through the <a href="https://wiki.archlinux.org/title/Arch_User_Repository">Arch User Repository (AUR)</a>.<br>
  The package descriptions can be used <a href="https://wiki.archlinux.org/title/Arch_User_Repository#Getting_started">to create and install packages</a>.<br><br>
  Support: <a href="https://github.com/lldap/lldap/discussions/1044">Discussions</a><br>
  Package repository: <a href="https://aur.archlinux.org/packages">Arch User Repository</a><br><br>
<table>
  <tr>
    <td>Package name</td>
    <td>Maintainer</td>
    <td>Description</td>
  </tr>
  <tr>
    <td><a href="https://aur.archlinux.org/packages/lldap">lldap</a></td>
    <td><a href="https://github.com/Zepmann">@Zepmann</a></td>
    <td>Builds the latest stable version.</td>
  </tr>
  <tr>
    <td><a href="https://aur.archlinux.org/packages/lldap-bin">lldap-bin</a></td>
    <td><a href="https://github.com/Zepmann">@Zepmann</a></td>
    <td>Uses the latest pre-compiled binaries from the <a href="https://github.com/lldap/lldap/releases">releases in this repository</a>.<br>
        This package is recommended if you want to run LLDAP on a system with limited resources.</td>
  </tr>
  <tr>
    <td><a href="https://aur.archlinux.org/packages/lldap-git">lldap-git</a></td>
    <td></td>
    <td>Builds the latest main branch code.</td>
  </tr>
</table>
LLDAP configuration file: /etc/lldap.toml<br>
</details>
<details>
<summary><b>Debian</b></summary>
<br>
  Unofficial Debian support is offered through the <a href="https://build.opensuse.org/">openSUSE Build Service</a>.<br><br>
  Maintainer: <a href="https://github.com/Masgalor">@Masgalor</a><br>
  Support: <a href="https://codeberg.org/Masgalor/LLDAP-Packaging/issues">Codeberg</a>, <a href="https://github.com/lldap/lldap/discussions">Discussions</a><br>
  Package repository: <a href="https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap">SUSE openBuildService</a><br>
<table>
  <tr>
    <td>Available packages:</td>
    <td>lldap</td>
    <td>Light LDAP server for authentication.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-extras</td>
    <td>Meta-Package for LLDAP and its tools and extensions.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-migration-tool</td>
    <td>CLI migration tool to go from OpenLDAP to LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-set-password</td>
    <td>CLI tool to set a user password in LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-cli</td>
    <td>LLDAP-CLI is an unofficial command line interface for LLDAP.</td>
  </tr>
</table>
LLDAP configuration file: /etc/lldap/lldap_config.toml<br>
</details>
<details>
<summary><b>CentOS</b></summary>
<br>
  Unofficial CentOS support is offered through the <a href="https://build.opensuse.org/">openSUSE Build Service</a>.<br><br>
  Maintainer: <a href="https://github.com/Masgalor">@Masgalor</a><br>
  Support: <a href="https://codeberg.org/Masgalor/LLDAP-Packaging/issues">Codeberg</a>, <a href="https://github.com/lldap/lldap/discussions">Discussions</a><br>
  Package repository: <a href="https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap">SUSE openBuildService</a><br>
<table>
  <tr>
    <td>Available packages:</td>
    <td>lldap</td>
    <td>Light LDAP server for authentication.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-extras</td>
    <td>Meta-Package for LLDAP and its tools and extensions.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-migration-tool</td>
    <td>CLI migration tool to go from OpenLDAP to LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-set-password</td>
    <td>CLI tool to set a user password in LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-cli</td>
    <td>LLDAP-CLI is an unofficial command line interface for LLDAP.</td>
  </tr>
</table>
LLDAP configuration file: /etc/lldap/lldap_config.toml<br>
</details>
<details>
<summary><b>Fedora</b></summary>
<br>
  Unofficial Fedora support is offered through the <a href="https://build.opensuse.org/">openSUSE Build Service</a>.<br><br>
  Maintainer: <a href="https://github.com/Masgalor">@Masgalor</a><br>
  Support: <a href="https://codeberg.org/Masgalor/LLDAP-Packaging/issues">Codeberg</a>, <a href="https://github.com/lldap/lldap/discussions">Discussions</a><br>
  Package repository: <a href="https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap">SUSE openBuildService</a><br>
<table>
  <tr>
    <td>Available packages:</td>
    <td>lldap</td>
    <td>Light LDAP server for authentication.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-extras</td>
    <td>Meta-Package for LLDAP and its tools and extensions.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-migration-tool</td>
    <td>CLI migration tool to go from OpenLDAP to LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-set-password</td>
    <td>CLI tool to set a user password in LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-cli</td>
    <td>LLDAP-CLI is an unofficial command line interface for LLDAP.</td>
  </tr>
</table>
LLDAP configuration file: /etc/lldap/lldap_config.toml<br>
</details>
<details>
<summary><b>OpenSUSE</b></summary>
<br>
  Unofficial OpenSUSE support is offered through the <a href="https://build.opensuse.org/">openSUSE Build Service</a>.<br><br>
  Maintainer: <a href="https://github.com/Masgalor">@Masgalor</a><br>
  Support: <a href="https://codeberg.org/Masgalor/LLDAP-Packaging/issues">Codeberg</a>, <a href="https://github.com/lldap/lldap/discussions">Discussions</a><br>
  Package repository: <a href="https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap">SUSE openBuildService</a><br>
<table>
  <tr>
    <td>Available packages:</td>
    <td>lldap</td>
    <td>Light LDAP server for authentication.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-extras</td>
    <td>Meta-Package for LLDAP and its tools and extensions.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-migration-tool</td>
    <td>CLI migration tool to go from OpenLDAP to LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-set-password</td>
    <td>CLI tool to set a user password in LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-cli</td>
    <td>LLDAP-CLI is an unofficial command line interface for LLDAP.</td>
  </tr>
</table>
LLDAP configuration file: /etc/lldap/lldap_config.toml<br>
</details>
<details>
<summary><b>Ubuntu</b></summary>
<br>
  Unofficial Ubuntu support is offered through the <a href="https://build.opensuse.org/">openSUSE Build Service</a>.<br><br>
  Maintainer: <a href="https://github.com/Masgalor">@Masgalor</a><br>
  Support: <a href="https://codeberg.org/Masgalor/LLDAP-Packaging/issues">Codeberg</a>, <a href="https://github.com/lldap/lldap/discussions">Discussions</a><br>
  Package repository: <a href="https://software.opensuse.org//download.html?project=home%3AMasgalor%3ALLDAP&package=lldap">SUSE openBuildService</a><br>
<table>
  <tr>
    <td>Available packages:</td>
    <td>lldap</td>
    <td>Light LDAP server for authentication.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-extras</td>
    <td>Meta-Package for LLDAP and its tools and extensions.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-migration-tool</td>
    <td>CLI migration tool to go from OpenLDAP to LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-set-password</td>
    <td>CLI tool to set a user password in LLDAP.</td>
  </tr>
  <tr>
    <td></td>
    <td>lldap-cli</td>
    <td>LLDAP-CLI is an unofficial command line interface for LLDAP.</td>
  </tr>
</table>
LLDAP configuration file: /etc/lldap/lldap_config.toml<br>
</details>
<details>
<summary><b>FreeBSD</b></summary>
<br>
  Official FreeBSD support is offered through the <a href="https://www.freshports.org/">FreeBSD Freshport Build Service</a>.<br><br>
  Maintainer: <a href="https://github.com/aokblast">@aokblast</a><br>
  Support: <a href="https://bugs.freebsd.org/bugzilla/">Bugzilla</a>, <a href="https://github.com/lldap/lldap/discussions">Discussions</a><br>
  Package repository: <a href="https://www.freshports.org/net/lldap/">FreeBSD Freshport Build</a><br>
  FreeBSD Setup and Migration Manual: <a href="https://github.com/lldap/lldap/blob/main/example_configs/freebsd/freebsd-install.md"> Using FreeBSD </a><br>
<table>
  <tr>
    <td>Available packages:</td>
    <td>lldap</td>
    <td>Light LDAP server for authentication.</td>
  </tr>
</table>
LLDAP configuration file: /usr/local/lldap_server/lldap_config.toml<br>
</details>

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
