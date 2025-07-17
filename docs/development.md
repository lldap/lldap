# Developing LLDAP

This page contains information about setting up your development environment, and compiling/deploying LLDAP from source.

**NOTE:** LLDAP consists of two executables (the `lldap` backend and the `lldap_app_bg.wasm` WASM frontend) and some static files. The executables need to be compiled separately, and the backend server needs to be aware when to find the assets (WASM frontend + static files) with the `assets_path` configuration option in your `lldap_config.toml`.

## Quickstart

The short version is:

```
git clone https://github.com/lldap/lldap
cd lldap
./app/build.sh
cargo run -- run
```

If you feel confused, please read on.

## Dependencies

Working on LLDAP requires:

- the latest stable or nightly [Rust](https://rust-lang.org/) release:
  - with [rustup](https://rustup.rs/) (recommended)
  - with your system packages (may be out-of-date and fail to compile)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/):
  - with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall) (recommended): `cargo binstall wasm-pack`
  - with basic cargo: `cargo install wasm-pack`
- `curl` and `gzip`: any version from your system should do the trick

## Frontend

The frontend code is located in the `app/` folder. To compile the frontend WASM, run the `./app/build.sh` script. You'll need to run this after every front-end change to
update the WASM package served.

Files and folders contained in `app/` need to be readable by the `lldap` server. The server will look for them in the
configured `assets_path` folder. By default, it will try to find `./app` which will work if you run the server from
the project root during development.

## Backend

The backend server (the `lldap` CLI) can be compiled using standard `cargo` commands.

**NOTE:** In release mode, LLDAP uses extensive optimization parameters which will make compilation very slow even on
decent hardware. Make debug builds during development.

- Running a debug build: `cargo run -- run`
- Running a release build (slower compilation): `cargo run --release -- run`

## Cross-compilation

To cross-compile LLDAP to a different hardware architecture, it's highly recommended
to install [`cross`](https://github.com/rust-embedded/cross):

- with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall) (recommended): `cargo binstall cross`
- from source or from release binaries, see [cross installation instructions](https://github.com/cross-rs/cross?tab=readme-ov-file#installation)

Then you can replace your `cargo` calls with `cross`, specifying the `--target=TRIPPLET` of your choice, where the list of available
target triplets and their level of support are found [on the official Rust docs](https://doc.rust-lang.org/beta/rustc/platform-support.html).

For example: 

```sh
./app/build.sh
cross build --target=armv7-unknown-linux-musleabihf -p lldap --release
```

**NOTE:** If you are deploying LLDAP to a remote device, don't forget to copy the assets contained in the `app/` directory, too!

## Architecture

For a global overview of the project structure, refer to [architecture.md](architecture.md).

## Deployment

For further deployment considerations, refer to the [From source section of the install docs](./install.md#from-source).
